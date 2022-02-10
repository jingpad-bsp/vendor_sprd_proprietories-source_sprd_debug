LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= systemDebuggerd.cpp

LOCAL_MODULE:= systemDebuggerd
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_EXECUTABLES)
LOCAL_CFLAGS := -Wall
LOCAL_MODULE_TAGS:= optional

LOCAL_SHARED_LIBRARIES := liblog libbase libcutils
LOCAL_INIT_RC := systemDebuggerd.rc
include $(BUILD_EXECUTABLE)

CUSTOM_MODULES += systemDebuggerd




include $(CLEAR_VARS)
LOCAL_SRC_FILES:= minidump.cpp

LOCAL_MODULE:= minidumpd
LOCAL_MODULE_PATH :=$(PRODUCT_OUT)/system/bin
LOCAL_CFLAGS := -Wall
LOCAL_MODULE_TAGS:= optional

LOCAL_SHARED_LIBRARIES := liblog libbase libcutils
LOCAL_INIT_RC := minidumpd.rc
include $(BUILD_EXECUTABLE)

CUSTOM_MODULES += minidumpd
