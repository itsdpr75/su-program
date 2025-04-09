/*
 * Copyright (C) 2023 Custom AOSP Build
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <selinux/selinux.h>
#include <log/log.h> // Para ALOG

#define DEFAULT_SHELL "/system/bin/sh"
#define FALLBACK_SHELL "/bin/sh"
#define DEFAULT_CONTEXT "u:r:su:s0"
#define LOG_FILE "/cache/su.log"

// Estructura para usuarios permitidos
typedef struct allowed_user {
    uid_t uid;
    char *name;
} allowed_user_t;

// Lista de usuarios permitidos por defecto (root y shell)
static allowed_user_t default_allowed_users[] = {
    { 0, "root" },
    { 2000, "shell" },
    { -1, NULL }
};

// Verifica si un usuario está autorizado
static int is_user_allowed(uid_t uid) {
    allowed_user_t *user = default_allowed_users;
    while (user->uid != -1) {
        if (user->uid == uid) return 1;
        user++;
    }
    return 0;
}

// Establece el contexto SELinux
static int set_selinux_context(const char *context) {
    if (!is_selinux_enabled()) return 0;
    
    const char *target_context = context ? context : DEFAULT_CONTEXT;
    if (setexeccon(target_context) < 0) {
        ALOGE("su: No se pudo establecer el contexto SELinux: %s", strerror(errno));
        return -1;
    }
    return 0;
}

// Registra intentos de uso de su
static void log_su_attempt(uid_t from_uid, uid_t to_uid, int success) {
    FILE *log_file;
    char log_entry[256];
    struct passwd *pw_from = getpwuid(from_uid);
    struct passwd *pw_to = getpwuid(to_uid);
    
    snprintf(log_entry, sizeof(log_entry), "su: %s(%d) -> %s(%d) [%s]\n",
             pw_from ? pw_from->pw_name : "unknown", from_uid,
             pw_to ? pw_to->pw_name : "unknown", to_uid,
             success ? "SUCCESS" : "FAILURE");
    
    log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fputs(log_entry, log_file);
        fclose(log_file);
    } else {
        ALOGI("%s", log_entry); // Fallback a ALOG si falla el archivo
    }
}

// Cambia al usuario y grupo objetivo
static int switch_user(uid_t to_uid, gid_t to_gid) {
    if (setresgid(to_gid, to_gid, to_gid) < 0) {
        ALOGE("su: No se pudo establecer el gid: %s", strerror(errno));
        return -1;
    }
    if (setresuid(to_uid, to_uid, to_uid) < 0) {
        ALOGE("su: No se pudo establecer el uid: %s", strerror(errno));
        return -1;
    }
    return 0;
}

// Ejecuta un comando como otro usuario
static int exec_command(uid_t to_uid, gid_t to_gid, char *const argv[], char *context) {
    pid_t pid = fork();
    if (pid < 0) {
        ALOGE("su: fork falló: %s", strerror(errno));
        return -1;
    }
    
    if (pid == 0) { // Proceso hijo
        if (set_selinux_context(context) < 0 || switch_user(to_uid, to_gid) < 0) {
            _exit(EXIT_FAILURE);
        }
        execvp(argv[0], argv);
        ALOGE("su: exec falló para %s: %s", argv[0], strerror(errno));
        _exit(EXIT_FAILURE);
    } else { // Proceso padre
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            ALOGE("su: waitpid falló: %s", strerror(errno));
            return -1;
        }
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    uid_t from_uid = getuid();
    uid_t to_uid = 0; // Por defecto: root
    gid_t to_gid = 0;
    char *shell = DEFAULT_SHELL;
    char *context = NULL;
    int opt_login = 0, opt_preserve = 0;
    int arg_index = 1;
    char *command = NULL;
    char **exec_args = NULL;
    int exec_argc = 0;
    struct passwd *pw;

    // Verificar permisos
    if (!is_user_allowed(from_uid)) {
        fprintf(stderr, "su: Permiso denegado\n");
        log_su_attempt(from_uid, to_uid, 0);
        return EXIT_FAILURE;
    }

    // Procesar opciones
    while (arg_index < argc && argv[arg_index][0] == '-') {
        if (!strcmp(argv[arg_index], "-") || !strcmp(argv[arg_index], "-l")) {
            opt_login = 1;
        } else if (!strcmp(argv[arg_index], "-p") || !strcmp(argv[arg_index], "--preserve-environment")) {
            opt_preserve = 1;
        } else if (!strcmp(argv[arg_index], "-c")) {
            if (arg_index + 1 < argc) command = argv[++arg_index];
            else {
                fprintf(stderr, "su: -c requiere un argumento\n");
                return EXIT_FAILURE;
            }
        } else if (!strcmp(argv[arg_index], "--context") || !strcmp(argv[arg_index], "-Z")) {
            if (arg_index + 1 < argc) context = argv[++arg_index];
            else {
                fprintf(stderr, "su: --context requiere un argumento\n");
                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr, "su: Opción desconocida: %s\n", argv[arg_index]);
            return EXIT_FAILURE;
        }
        arg_index++;
    }

    // Determinar usuario objetivo
    if (arg_index < argc) {
        pw = getpwnam(argv[arg_index]);
        if (!pw) {
            fprintf(stderr, "su: Usuario desconocido: %s\n", argv[arg_index]);
            return EXIT_FAILURE;
        }
        to_uid = pw->pw_uid;
        to_gid = pw->pw_gid;
        shell = pw->pw_shell;
        arg_index++;
    } else {
        pw = getpwuid(to_uid);
        if (pw) shell = pw->pw_shell;
    }

    // Verificar shell
    if (access(shell, X_OK) != 0) shell = FALLBACK_SHELL;

    // Registrar intento
    log_su_attempt(from_uid, to_uid, 1);

    // Configurar argumentos para exec
    if (command) {
        exec_argc = 3;
        exec_args = malloc(sizeof(char *) * (exec_argc + 1));
        if (!exec_args) {
            fprintf(stderr, "su: Error de memoria\n");
            return EXIT_FAILURE;
        }
        exec_args[0] = shell;
        exec_args[1] = "-c";
        exec_args[2] = command;
        exec_args[3] = NULL;
    } else if (arg_index < argc) {
        exec_argc = argc - arg_index + 1;
        exec_args = malloc(sizeof(char *) * (exec_argc + 1));
        if (!exec_args) {
            fprintf(stderr, "su: Error de memoria\n");
            return EXIT_FAILURE;
        }
        exec_args[0] = shell;
        for (int i = 0; i < exec_argc - 1; i++) exec_args[i + 1] = argv[arg_index + i];
        exec_args[exec_argc] = NULL;
    } else {
        exec_argc = 1;
        exec_args = malloc(sizeof(char *) * (exec_argc + 1));
        if (!exec_args) {
            fprintf(stderr, "su: Error de memoria\n");
            return EXIT_FAILURE;
        }
        if (opt_login) {
            char *arg0 = malloc(strlen(shell) + 2);
            if (!arg0) {
                fprintf(stderr, "su: Error de memoria\n");
                free(exec_args);
                return EXIT_FAILURE;
            }
            sprintf(arg0, "-%s", strrchr(shell, '/') ? strrchr(shell, '/') + 1 : shell);
            exec_args[0] = arg0;
        } else {
            exec_args[0] = shell;
        }
        exec_args[1] = NULL;
    }

    // Configurar entorno para shell de login
    if (opt_login && !opt_preserve) {
        clearenv();
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", shell, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        setenv("PATH", "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin:/odm/bin", 1);
        if (chdir(pw->pw_dir) < 0) {
            ALOGW("su: No se pudo cambiar al directorio: %s: %s", pw->pw_dir, strerror(errno));
        }
    }

    // Ejecutar comando
    int result = exec_command(to_uid, to_gid, exec_args, context);

    // Liberar memoria
    if (opt_login && exec_args[0] != shell) free(exec_args[0]);
    free(exec_args);

    return result;
}
