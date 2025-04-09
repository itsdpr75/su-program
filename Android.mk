LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := custom_su
LOCAL_MODULE_TAGS := optional #user userdebug
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
LOCAL_SRC_FILES := su.c
LOCAL_SHARED_LIBRARIES := \
    libcutils \
    liblog \
    libselinux

# Compilar para 32 y 64 bits
LOCAL_MULTILIB := both

# Configuraciones para 64 bits
LOCAL_MODULE_STEM_64 := custom_su
LOCAL_MODULE_PATH_64 := $(TARGET_OUT_EXECUTABLES)

# Configuraciones para 32 bits
LOCAL_MODULE_STEM_32 := custom_su_32
LOCAL_MODULE_PATH_32 := $(TARGET_OUT_OPTIONAL_EXECUTABLES)

# Instalar en /system/xbin
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_OWNER := root
# LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)  # /system/xbin
LOCAL_MODULE_RELATIVE_PATH := xbin # Para instalarlo automaticamente
# Establecer permisos y contexto SELinux
LOCAL_POST_INSTALL_CMD := $(hide) \
    chmod 6755 $(TARGET_OUT)/xbin/c_su; \
    chcon u:object_r:su_exec:s0 $(TARGET_OUT)/xbin/c_su

include $(BUILD_EXECUTABLE)
