LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= nhMonitorService.cpp
LOCAL_MODULE:= nhMonitorService
LOCAL_CFLAGS := -Wall
LOCAL_MODULE_TAGS:= optional
LOCAL_SHARED_LIBRARIES := liblog libbase libcutils
LOCAL_INIT_RC := nhMonitorService.rc
include $(BUILD_EXECUTABLE)

CUSTOM_MODULES += nhMonitorService

