LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := wificurse
LOCAL_SRC_FILES := ../src/ap_list.c ../src/console.c ../src/error.c ../src/iw.c ../src/wificurse.c
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../src
LOCAL_CFLAGS := -O2 -Wall
include $(BUILD_EXECUTABLE)
