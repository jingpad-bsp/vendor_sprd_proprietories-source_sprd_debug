#define LOG_TAG "nhMonitorService"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cutils/properties.h>
#include <cutils/log.h>
#include <fcntl.h>
#include <errno.h>
#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <poll.h>
#include <unistd.h>
#include <grp.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/time.h>
#include <time.h>

#define UNISOC_NHMONITOR_PERSIST_PROP  "persist.vendor.nhmonitor"
#define UNISOC_NHMONITOR_AMS_PROP      "debug.vendor.nhmonitor.status"
#define UNISOC_NHMONITOR_TOTALTIMEOUT  60   //60 seconds
static  char sdcardWdtPath[100];
static  char configWdtPath[100];

static char nhmonitor_buf[PROPERTY_VALUE_MAX];

//Unisoc: block may happen before AMS.watchdog is ready. so nhMonitorService will be used
//        to detect this scene. this will always work no matter if kernel native hung detect
//        active or not. If active, we should feed watchdog.
void monitorHungBeforeWDTHandler(int timeout){
    int checkWDTHandlerTime = 0;
    if(timeout < 20)
        timeout = 20;
    ALOGD("nhmonitorService: monitorHungBeforeWDTHandler enter:%d",timeout);

    //wait for ams.watchdog ready by checking the property of UNISOC_NHMONITOR_AMS_PROP
    while(checkWDTHandlerTime < timeout){
        property_get(UNISOC_NHMONITOR_AMS_PROP, nhmonitor_buf, "false");
        if(strcmp(nhmonitor_buf,"true") == 0){
            //AMS Watchdog WDTHandler is ok now
            ALOGD("nhmonitorService: WDTHandler is ok now");
            break;
        }
        checkWDTHandlerTime++;
        sleep(1);
        ALOGD("nhmonitorService: wait for WDTHandler ready");
    }
    if(checkWDTHandlerTime >= timeout){
        //Failed to get WDTHandler, some exception must happen
        //now try to keep logs by dumpstate
        ALOGD("nhmonitorService: block happen before WDTHandler ready");
        property_set("ctl.start", "bugreportW");
    }
}

//unisoc: wait for sdcard ready. system will always mount the external sdcard a little bit later
//        if sdcard is ok, we will go further to check if the directory of "wdt" exists here.
//        wdt dump file will be backup here.
bool waitSdcard(int timeout){
    bool sdcardOK = false;
    ALOGD("nhmonitorService: waitSdcard enter:%d",timeout);

    while(!sdcardOK && timeout>0){
        property_get("vold.sdcard0.state", nhmonitor_buf, "");
        ALOGD("nhmonitorService: vold.sdcard0.state=%s",nhmonitor_buf);
        if(strcmp(nhmonitor_buf,"mounted") == 0){
            ALOGD("nhmonitorService: SDCARD wdt is ok");
            sdcardOK = true;
            property_get("vold.sdcard0.path", nhmonitor_buf, "");
            strcpy(sdcardWdtPath,"/mnt/media_rw/");
            strcat(sdcardWdtPath,(char*)(nhmonitor_buf+9));
            strcat(sdcardWdtPath,"/wdt/bugreport-wdt-Log.zip");
            property_get("vold.sdcard0.path", nhmonitor_buf, "");
            strcpy(configWdtPath,nhmonitor_buf);
            strcat(configWdtPath,"/wdt/config.ini");
            ALOGD("nhmonitorService: SDCARD wdtpath=%s, ini path=%s",sdcardWdtPath,configWdtPath);
         
        }else{
            ALOGD("nhmonitorService: sdcard not ok :%d,%s",timeout,strerror(errno));
            sleep(1);
            timeout--;
        }  
    }
    return sdcardOK;
}

//Unisoc: nhMonitorService will check if config.ini existing in /cache/wdt or sdcard/wdt
//        std::string  config;       config string,each byte means one function
//                                   byte1 '1'  open sysdump
//                                   byte2 '1'  backup wdt dump file to cache&sdcard
//                                   others:    reserved
struct WDTConfig{
	std::string  config;
} ;
 bool checkConfigFile(WDTConfig& wdtconfig){
    wdtconfig.config = "";
    android::base::unique_fd fdConfig(TEMP_FAILURE_RETRY(open(configWdtPath,O_RDONLY | O_NONBLOCK | O_CLOEXEC)));
    if(fdConfig < 0){
        ALOGD("nhmonitorService: No config file found:%s",strerror(errno));
        return false;
    }
    char buffer[512];
    int  end = 0;
    char *strBuffer;
    ssize_t bytes_read = TEMP_FAILURE_RETRY(read(fdConfig, buffer, sizeof(buffer)));
    if (bytes_read > 0) {
        strBuffer = buffer;
        while(end < bytes_read){
            if(buffer[end]==0xd){
                buffer[end]=0;
                ALOGD("nhmonitorService: find a line= %s",strBuffer);
                wdtconfig.config = strBuffer;
                break;
            }else
                end++;
        }
		
        ALOGD("nhmonitorService: config=%s",wdtconfig.config.c_str());  
    } else {
        ALOGD("nhmonitorService: read config.ini error");
    }

    return true;
}

//unisoc: main function of nhMonitorService
int main(int argc, char** argv) {
    int timeSpend = 0;
    int lastTime = time(NULL);
    //task1: check if backup wdt dump file
    if(waitSdcard(50)){
        WDTConfig  wdtConfig;
        bool sysdumpOn = false;
        bool saveResultOut = false;
        if(checkConfigFile(wdtConfig)){
            int size = wdtConfig.config.length();
            const char* str = wdtConfig.config.c_str();
            if(size > 0)
                sysdumpOn = str[0]=='1';
            if(size > 1)
               saveResultOut = str[1]=='1';
            ALOGD("nhmonitorService: config Value:%d,%d",sysdumpOn,saveResultOut);
        }
        if(sysdumpOn){
            property_set("debug.wdt.sysdump","on");
            ALOGD("nhmonitorService: try to open sysdump");
        }
	if(saveResultOut){
            //Unisoc: try to backup old WDT dump to sdcard
            property_set("debug.dumpstate.savepath", sdcardWdtPath);
        }
    }
    timeSpend += (time(NULL) - lastTime);
    ALOGD("nhmonitorService: sdcard check used:%d seconds",timeSpend);

    //task2: try to monitor those block scene before ASM.watchdog ok
    //Unisoc: new Feature to monitor if ams.watchdog.WDTHandler OK.
    //        if not, try to do hung-exception when timeout
    //        WDTHandler should write a property to notify nhMonitorService of its ready
    monitorHungBeforeWDTHandler(UNISOC_NHMONITOR_TOTALTIMEOUT-timeSpend);
    
    return 1;
}

