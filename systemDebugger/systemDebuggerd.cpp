#define LOG_TAG "systemDebuggerd"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cutils/properties.h>
#include <cutils/log.h>
#include <fcntl.h>
#include <android-base/file.h>
#include <errno.h>
#include "sysdumpdb.h"
#define SPRD_SYSDUMP_CONFIG   "/proc/sprd_sysdump"
#define SPRD_SYSDUMP_PROP   "persist.vendor.sysdump"
#define VERSION_INFO "ro.product.name"
#define DEBUG_FULLDUMP_PROP  "vendor.debug.sysdump.enabled"
#define DEFAULT_PROP_VALUE  "error"
/*for minidump */
struct dumpdb_header header_g;

int init_dump_status(void);
int set_dump_status(int ops_type);

//write flag to /proc/sprd_sysdump
int writeFile(const char* path, const char* content){
	int fd = TEMP_FAILURE_RETRY(open(path, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600));
	if (fd == -1) {
		ALOGE("write_file: Unable to open %s : %s\n",path, strerror(errno));
		return -1;
	}

	int result = android::base::WriteStringToFd(content, fd) ? 0 : -1;
	if (result == -1) {
		ALOGE("write_file: Unable to write to '%s': %s\n", path, strerror(errno));
	}

	close(fd);
	return result;
}

static int do_server(){
	FILE* fp;
	int result;
	char configBuffer[25];
	char sysdump_conf[PROPERTY_VALUE_MAX];
	char* conf;

	property_get(SPRD_SYSDUMP_PROP, sysdump_conf, "-1");
	ALOGD("sysdump_conf is %s",sysdump_conf);

	if( (strcmp(sysdump_conf,"on") != 0 )&&(strcmp(sysdump_conf,"off") != 0)){
		if(ERR_NO_PARTION != init_dump_status()) {
			ALOGD("partition exsist, init complete  . \n");
			return 0;
		}
		if ((fp = fopen(SPRD_SYSDUMP_CONFIG, "r"))){
			conf = fgets(configBuffer, sizeof(configBuffer), fp);
			ALOGD("gets config from %s = %s", SPRD_SYSDUMP_CONFIG,conf);
			if(strstr(conf,"1")) {
				property_set(SPRD_SYSDUMP_PROP, "on");
			} else if (strstr(conf,"0")) {
				property_set(SPRD_SYSDUMP_PROP, "off");
			}
			fclose(fp);
			ALOGD("Initial sysdump %s, from %s\n",conf,SPRD_SYSDUMP_CONFIG);
		} else {
			ALOGE(" Unable to open %s : %s\n", SPRD_SYSDUMP_CONFIG, strerror(errno));
			return -1;
		}
	} else {
		if(writeFile(SPRD_SYSDUMP_CONFIG, sysdump_conf) == -1)
			ALOGE("Error to write file %s - %s \n",SPRD_SYSDUMP_CONFIG,sysdump_conf);

		if(strcmp(sysdump_conf,"on") == 0)
			set_dump_status(FULL_DUMP_ENABLE);
		else if (strcmp(sysdump_conf,"off") == 0)
			set_dump_status(FULL_DUMP_DISENABLE);
		else
			ALOGE("sysdump_conf error \n");
	}

	return 0;
}

int tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c + 'a' - 'A';
    }
    else
    {
        return c;
    }
}
unsigned long stoh(char s[])
{
    int i;
    unsigned long n= 0;
    int num_max = strlen(s);
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
    {
        i = 2;
    }
    else
    {
        i = 0;
    }
    num_max -= i;
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z') && (i <= num_max);++i)
    {
        if (tolower(s[i]) > '9')
        {
            n = 16 * n + (10 + tolower(s[i]) - 'a');
        }
        else
        {
            n = 16 * n + (tolower(s[i]) - '0');
        }
    }
    return n;
}
/*  delete a directory recursively which is not empty
    @dir: absolute path of the directory
 */
int remove_dir(const char *dir)
{
        char cur_dir[] = ".";
        char up_dir[] = "..";
        char dir_name[128];
        DIR *dirp;
        struct dirent *dp;
        struct stat dir_stat;

        /* directory is not exist */
        if ( 0 != access(dir, F_OK) ) {
                return 0;
        }
        /* get property error */
        if ( 0 > stat(dir, &dir_stat) ) {
                perror("get directory stat error");
                return -1;
        }
        if ( S_ISREG(dir_stat.st_mode) ) {
                /* a regular file */
                remove(dir);
        } else if ( S_ISDIR(dir_stat.st_mode) ) {
                /* a directory */
                dirp = opendir(dir);
                while ( (dp=readdir(dirp)) != NULL ) {
                        /* ignore "." & ".." */
                        if ( (0 == strcmp(cur_dir, dp->d_name)) || (0 == strcmp(up_dir, dp->d_name)) ) {
                                continue;
                        }
                        sprintf(dir_name, "%s/%s", dir, dp->d_name);
                        /*      re-call the function */
                        remove_dir(dir_name);
                }
                closedir(dirp);
                /*delete empty dir */
                rmdir(dir);
        } else {
                perror("unknow file type!");
        }
        return 0;
}

int sysdumpdb_read(const char * sysdumpdb_path, char *databuf, int data_len, int data_offset) {
  int ret = 0;
  int len;
  int fd = -1;
  fd = open(sysdumpdb_path, O_RDONLY);
  if (fd >= 0) {
    ALOGD("%s open Ok sysdumpdb_path = %s ", __FUNCTION__, sysdumpdb_path);
    lseek(fd, data_offset, SEEK_SET);
    len = read(fd, databuf, data_len);
    if (len <= 0) {
      ret = -1;
      ALOGD("%s read fail sysdumpdb_path = %s ", __FUNCTION__, sysdumpdb_path);
    }
    close(fd);
    return len;
  } else {
    ALOGD("%s open fail sysdumpdb_path = %s ", __FUNCTION__, sysdumpdb_path);
    ret = -1;
  }
  return ret;
}
int sysdumpdb_write(const char * sysdumpdb_path, char *databuf, int data_len, int data_offset) {
  int len;
  int fd = -1;

  fd = open(sysdumpdb_path, O_WRONLY);
  if (fd >= 0) {
    ALOGD("%s open Ok sysdumpdb_path = %s ", __FUNCTION__, sysdumpdb_path);
#ifdef CONFIG_NAND
    __s64 up_sz = data_len;
    ret =ioctl(fd, UBI_IOCVOLUP, &up_sz);
    if(ret != 0 )
        ALOGD("%s UBI_IOCVOLUP err ! ret = %d", __FUNCTION__, ret);
    else
        ALOGD("%s UBI_IOCVOLUP ok ! ", __FUNCTION__);
#endif
    lseek(fd, data_offset, SEEK_SET);
    len = write(fd, databuf, data_len);

    if (len <= 0) {
      ALOGD("%s  write fail sysdumpdb_path = %s len = %d ", __FUNCTION__, sysdumpdb_path, len);
      close(fd);
      return len;
    }
    fsync(fd);
    close(fd);
    return len;
  } else {
    ALOGD("%s open fail sysdumpdb_path = %s ", __FUNCTION__, sysdumpdb_path);
    return -1;
  }
}
int prepare_info_desc(void){
	FILE *fp;
	int nread=0;
	size_t len = 0;
	char *buf=NULL;
	char *buffer=NULL;
	char content[16]="";
	char info_path[128] = {0};
	/* read /proc/sysdumpdb/minidump_info and save it in minidump_g */
	memset(info_path, 0, sizeof(info_path));
	snprintf(info_path, sizeof(info_path), "%s/%s/%s", PROC_DIR, MINIDUMP_INFO_DIR, MINIDUMP_INFO_PROC);
	fp = fopen(info_path, "r");
	if (fp != NULL) {
		while((nread = getline(&buffer, &len, fp)) != -1) {
			/*	minidump_info_paddr	*/
			if((buf=strstr(buffer, GET_MINIDUMP_INFO_NAME(MINIDUMP_INFO_PADDR)))!=NULL){ /* find the string line*/
				buffer[strlen(buffer)-1]='|'; 			/* truncate the string,terminal by '|'*/
				sscanf(buffer, "%*[^:]:%[^|]", content);            /* get value between ':' and '|'*/
				header_g.minidump_info_desc.paddr = stoh(content);
			}
			/*	minidump_info_size	*/
			if((buf=strstr(buffer, GET_MINIDUMP_INFO_NAME(MINIDUMP_INFO_SIZE)))!=NULL){ /* find the string line*/
				buffer[strlen(buffer)-1]='|'; 			/* truncate the string,terminal by '|'*/
				sscanf(buffer, "%*[^:]:%[^|]", content);            /* get value between ':' and '|'*/
				header_g.minidump_info_desc.size = stoh(content);
			}
		}
		fclose(fp);
	} else {
		ALOGD("%s open fail info_path = %s ", __FUNCTION__, info_path);
		return -1;
	}

	return 0;
}
/* update header infomation:MAGIC ,desc .. */
int update_dumpdb_header(const char *sysdumpdb_path)
{
	int size = sizeof(header_g);
	/* clear uboot magic, set app magic	*/
	memset(header_g.uboot_magic, 0 , strlen(UBOOT_MAGIC));
	memcpy(header_g.app_magic, APP_MAGIC, strlen(APP_MAGIC));
	if(prepare_info_desc()){
		ALOGD("%s:prepare_info_desc fail ", __FUNCTION__);
		return -1;
	}
	if(size != sysdumpdb_write(sysdumpdb_path, (char*)(&header_g), size, 0)){
		ALOGD("%s:write  header fail ,sysdumpdb path : %s", __FUNCTION__, sysdumpdb_path);
		return -1;
	}
	ALOGD("%s ok  path :%s ", __FUNCTION__, sysdumpdb_path);
	return 0;
}
int prepare_dir(char *path)
{
        char oldname[100], newname[100];
        int i,ret;
        /*      first , detect if 0 ~ 4 files exist , if not ,create it */
        for(i = 1;i < DIR_MAX_NUM;i++){
                sprintf(oldname, "%s/%d", path, i);
                if(access(oldname, NULL) != 0){
                        printf("file %d not exist , create\n", i);
                        break;
                }
                printf("file %s is exist .\n", oldname);
        }
        /* delete the largest number dir*/
        if(DIR_MAX_NUM == i) {
                sprintf(oldname, "%s/%d", path, DIR_MAX_NUM);
                if(!remove_dir(oldname))
                        ALOGD("Delete file : (%s)  OK  ", oldname);
                else
                        ALOGE("Delete file : (%s)  Fail  ", oldname);
        }
        if(i != 1){
                for( i=i-1 ;i > 0;i--){
                        sprintf(oldname, "%s/%d", path, i);
                        sprintf(newname, "%s/%d", path, i + 1);
                        if(rename(oldname, newname) == 0)
                                printf("file %s ----change to ---> %s.\n", oldname, newname);
			else
				return -1;
                }
        }
        /* create file 1*/
        sprintf(oldname, "%s/%d", path, 1);
        ret = mkdir(oldname,0777);
	if(ret){
		ALOGE("Unable to mkdir   %s \n", oldname);
		return -1;
	}

	ret = chmod(oldname, 0777);
	if(ret){
		ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
		return -1;
	}
	return 0;
}
int save_minidump_data(struct minidump_info *minidump_infop, const char *sysdumpdb_path)
{
	int i = 0;
	int ret;
	int data_offset = sizeof(struct dumpdb_header) + sizeof(struct minidump_info);
	char buf[100]={0};
	FILE *fp = NULL;
	char *data_buf = NULL;
	int data_len = 0;
	int file_index = 1;

	ALOGD("%s in ", __FUNCTION__);
	/*	check '/data/minidump dir exist '*/
	if(access(MINIDUMP_FILE_PATH, NULL)!=0){
		ALOGD("%s is not exist", MINIDUMP_FILE_PATH);
		ret = mkdir(MINIDUMP_FILE_PATH,0777);
		if(ret){
			ALOGE("Unable to mkdir   %s . %s \n", MINIDUMP_FILE_PATH,strerror(errno));
			return -1;
		}
	} else {
		ALOGD("%s is exist ", MINIDUMP_FILE_PATH);
		ret = chmod(MINIDUMP_FILE_PATH, 0777);
		if(ret){
			ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
			return -1;
		}
	}
	if(prepare_dir(MINIDUMP_FILE_PATH)){
		ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
	}

	data_offset += data_len;
	/*	handle	| struct pt_regs |	*/
	if( minidump_infop->compressed){
		data_len = minidump_infop->regs_info.size_comp;
	} else {
		data_len = minidump_infop->regs_info.size;
	}
	data_buf = (char*)malloc(data_len);
	if(NULL == data_buf){
		ALOGD("%s: malloc data_buf fail ", __FUNCTION__);
		return -1;
	}
	ALOGE("pt_regs offfset: 0x%x data_len:0x%x \n", data_offset, data_len);
	if(data_len != sysdumpdb_read(sysdumpdb_path, data_buf, data_len, data_offset)){
		ALOGD("read sysdumpdb_data error  \n ");
		free(data_buf);
		return -1;
	}
	if( minidump_infop->compressed){
		sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME"%s", file_index, "regs", ".gz");
	} else {
		sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME, file_index, "regs");
	}
	file_index ++;
	if((fp = fopen(buf,"w")) == NULL){
		ALOGD("create %s fail .\n", buf);
		free(data_buf);
		return -1;
	}
	ret = chmod(buf, 0666);
	if(ret)
		ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
	ALOGD("create %s ok !\n", buf);
	fwrite(data_buf, 1, data_len, fp);
	fclose(fp);
	fp = NULL;
	free(data_buf);

	/* 	handle	| memory amount regs | */
	for(i=0;i<minidump_infop->regs_info.num;i++){
		if(minidump_infop->regs_memory_info.reg_paddr[i] == 0)
			continue;
		/*	indicate data offset in sysdumpdb partition	*/
		data_offset += data_len;

		if( minidump_infop->compressed){
			data_len = minidump_infop->regs_memory_info.per_mem_size_comp[i];
		} else {
			data_len = minidump_infop->regs_memory_info.per_reg_memory_size;
		}
		data_buf = (char*)malloc(data_len);
		if(NULL == data_buf){
			ALOGD("%s: malloc data_buf fail ", __FUNCTION__);
			return -1;
		}
		ALOGE("memory amount regs  offfset: 0x%x data_len :0x%x \n", data_offset, data_len);
		if(data_len != sysdumpdb_read(sysdumpdb_path, data_buf, data_len, data_offset)){
			ALOGD("read sysdumpdb_data error  \n ");
			free(data_buf);
			return -1;
		}

		if( minidump_infop->compressed){
			sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME"_R%d""%s", file_index, "regs", i, ".gz");
		} else {
			sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME"_R%d", file_index, "regs", i);
		}
		file_index ++;
		if((fp = fopen(buf,"w")) == NULL){
			ALOGD("create %s fail !\n", buf);
			free(data_buf);
			return -1;
		}
		ret = chmod(buf, 0666);
		if(ret)
			ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
		ALOGD("create %s ok !\n", buf);
		fwrite(data_buf, 1, data_len, fp);
		fclose(fp);
		fp = NULL;
		free(data_buf);
	}
	/*	handle	| sections | 	*/
	for(i=0;i<minidump_infop->section_info_total.total_num;i++){

		data_offset += data_len;
		if( minidump_infop->compressed){
			data_len = minidump_infop->section_info_total.section_info[i].section_size_comp;
		} else {
			data_len = minidump_infop->section_info_total.section_info[i].section_size;
		}
		ALOGD("%s: section:%s, size:%x ", __FUNCTION__, minidump_infop->section_info_total.section_info[i].section_name, minidump_infop->section_info_total.section_info[i].section_size);
		data_buf = (char*)malloc(data_len);
		if(NULL == data_buf){
			ALOGD("%s: malloc data_buf fail ", __FUNCTION__);
			return -1;
		}

		ALOGE("%s section  offfset: 0x%x data_len :0x%x \n", minidump_infop->section_info_total.section_info[i].section_name, data_offset, data_len);
		if(data_len != sysdumpdb_read(sysdumpdb_path, data_buf, data_len, data_offset)){
			ALOGD("read sysdumpdb_data error  \n ");
			free(data_buf);
			return -1;
		}

		if( minidump_infop->compressed){
			sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME"_%s""%s", file_index, "section", minidump_infop->section_info_total.section_info[i].section_name, ".gz");
		} else {
			sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME"_%s", file_index, "section", minidump_infop->section_info_total.section_info[i].section_name);
		}
		file_index ++;
		if((fp = fopen(buf,"w")) == NULL){
			ALOGD("create %s fail !\n", buf);
			free(data_buf);
			return -1;
		}
		ret = chmod(buf, 0666);
		if(ret)
			ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
		ALOGD("create %s ok !\n", buf);
		fwrite(data_buf, 1, data_len, fp);
		fclose(fp);
		fp = NULL;
		free(data_buf);
	}
	 /*      handle	minidump elfhdr	*/

	data_offset += data_len;
	if( minidump_infop->compressed){
		data_len = minidump_infop->minidump_elfhdr_size_comp;
	} else {
		data_len = minidump_infop->minidump_elfhdr_size;
	}
	data_buf = (char*)malloc(data_len);
	if(NULL == data_buf){
		ALOGD("%s: malloc data_buf fail ", __FUNCTION__);
		return -1;
	}
	ALOGE("minidump elfhdr  offfset: 0x%x \n", data_offset);
	if(data_len != sysdumpdb_read(sysdumpdb_path, data_buf, data_len, data_offset)){
		ALOGD("read sysdumpdb_data error  \n ");
		free(data_buf);
		return -1;
	}

	if( minidump_infop->compressed){
		sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME"%s", 0, "elfhdr", ".gz");
	} else {
		sprintf(buf, MINIDUMP_FILE_PATH"/1/" MINIDUMP_FILE_NAME, 0, "elfhdr");
	}
	if((fp = fopen(buf,"w")) == NULL){
		ALOGD("create %s fail !\n", buf);
		free(data_buf);
		return -1;
	}
	ret = chmod(buf, 0666);
	if(ret)
		ALOGE("Unable to chmod  %d: %s \n", ret, strerror(errno));
	ALOGD("create %s ok !\n", buf);
	fwrite(data_buf, 1, data_len, fp);
	fclose(fp);
	fp = NULL;
	free(data_buf);



	ALOGD("%s out ", __FUNCTION__);
	return 0;
}
void show_minidump_info(struct minidump_info *minidump_infop)
{
        int i;

        ALOGD("kernel_magic: %s  \n ", minidump_infop->kernel_magic);

        ALOGD("---     regs_info       ---  \n ");
        ALOGD("arch:              %d \n ", minidump_infop->regs_info.arch);
        ALOGD("num:               %d \n ", minidump_infop->regs_info.num);
        ALOGD("paddr:         %x \n ", minidump_infop->regs_info.paddr);
        ALOGD("size:          %d \n ", minidump_infop->regs_info.size);

        ALOGD("---     regs_memory_info        ---  \n ");
        for(i=0;i<minidump_infop->regs_info.num;i++){
                ALOGD("reg[%d] paddr:          %x \n ", i, minidump_infop->regs_memory_info.reg_paddr[i]);
        }
        ALOGD("per_reg_memory_size:    %d \n ", minidump_infop->regs_memory_info.per_reg_memory_size);
        ALOGD("valid_reg_num:          %d \n ", minidump_infop->regs_memory_info.valid_reg_num);
        ALOGD("reg_memory_all_size:    %d \n ", minidump_infop->regs_memory_info.size);

        ALOGD("---     section_info_total        ---  \n ");
        ALOGD("Here are %d sections, Total size : %d \n", minidump_infop->section_info_total.total_num, minidump_infop->section_info_total.total_size);
        ALOGD("total_num:        %x \n ", minidump_infop->section_info_total.total_num);
        ALOGD("total_size        %x \n ", minidump_infop->section_info_total.total_size);
        for(i=0;i<minidump_infop->section_info_total.total_num;i++){
                ALOGD("section_name:           %s \n ", minidump_infop->section_info_total.section_info[i].section_name);
                ALOGD("section_start_vaddr:    %lx \n ", minidump_infop->section_info_total.section_info[i].section_start_vaddr);
                ALOGD("section_end_vaddr:      %lx \n ", minidump_infop->section_info_total.section_info[i].section_end_vaddr);
                ALOGD("section_start_paddr:    %x \n ", minidump_infop->section_info_total.section_info[i].section_start_paddr);
                ALOGD("section_end_paddr:      %x \n ", minidump_infop->section_info_total.section_info[i].section_end_paddr);
                ALOGD("section_size:           %x \n ", minidump_infop->section_info_total.section_info[i].section_size);
        }

        ALOGD("minidump_data_size:     %x \n ", minidump_infop->minidump_data_size);


        return;
}

int handle_minidump_data(const char *sysdumpdb_path)
{
	struct minidump_info minidump_info;
	int offset = sizeof(struct dumpdb_header);
	int data_len = sizeof(struct minidump_info);

	/*	read minidump info data	*/
	if(data_len != sysdumpdb_read(sysdumpdb_path, (char*)(&minidump_info), data_len, offset)){
		ALOGD("read minidump info data  error  \n ");
		return -1;
	}

	/*	check  minidump info data	*/
	if(memcmp(KERNEL_MAGIC, minidump_info.kernel_magic, strlen(KERNEL_MAGIC))){
		ALOGD("no kernel_magic , invalid minidump data \n ");
		return -1;
	}
	show_minidump_info(&minidump_info);
	if(save_minidump_data(&minidump_info, sysdumpdb_path)){
		ALOGD("save_minidump_data error .  \n ");
		return -1;
	}
	return 0;
}
int minidump_init(void){
	char sysdumpdb_path[PARTITION_NAME_MAX_SIZE];
	char prop[128] = {0};
	int size = sizeof(struct dumpdb_header);

	ALOGD("%s in\n", __func__);
	/*	Get sysdumpdb partition path	*/
	if (-1 == property_get("ro.vendor.product.partitionpath", prop, DEFAULT_PROP_VALUE)){
		ALOGD(" get partitionpath fail\n");
		return -1;
	}
	snprintf(sysdumpdb_path, sizeof(sysdumpdb_path), "%s%s", prop, SYSDUMPDB_PARTITION_NAME);

	if(size != sysdumpdb_read(sysdumpdb_path, (char *)(&header_g), size, 0)){
		ALOGD("read header error ,exit sysdumpdb init \n ");
		return -1;
	}
	/*check  UBOOT_MAGIC if exist. */
	if(memcmp(UBOOT_MAGIC, header_g.uboot_magic, strlen(UBOOT_MAGIC))){
		/*	no uboot magic , nothing saved .	*/
		ALOGD(" no uboot magic , nothing saved . Only update header \n ");
		update_dumpdb_header(sysdumpdb_path);
	} else {
		ALOGD(" uboot magic detect , need save dump contents .then update header \n ");
		/*	TODO: handle date in sysdumpdb saved by uboot */
		handle_minidump_data(sysdumpdb_path);
		update_dumpdb_header(sysdumpdb_path);
	}

	ALOGD("%s out\n", __func__);
	return 0;
}
void set_persist_prop(int flag){
	if(flag == 1) {
	   property_set(SPRD_SYSDUMP_PROP, "on");
	   ALOGD("set %s on", SPRD_SYSDUMP_PROP);
	} else if (flag == 0) {
	   property_set(SPRD_SYSDUMP_PROP, "off");
	   ALOGD("set %s off", SPRD_SYSDUMP_PROP);
	} else {
	   ALOGD("unvaild flag value = %d", flag);
	}
}
int init_dump_status(void)
{
	int ret = 0;
	char sysdumpdb_path[PARTITION_NAME_MAX_SIZE];
	char prop[128] = {0};
	int size = sizeof(struct dumpdb_header);
	int full_dump_flag = -1;
	int mini_dump_flag = -1;

	ALOGD("%s in\n", __func__);
	/*	Get sysdumpdb partition path	*/
	if (-1 == property_get("ro.vendor.product.partitionpath", prop, DEFAULT_PROP_VALUE)){
		ALOGD(" get partitionpath fail\n");
		return ERR_NORMAL;
	}
	snprintf(sysdumpdb_path, sizeof(sysdumpdb_path), "%s%s", prop, SYSDUMPDB_PARTITION_NAME);

	if(size != sysdumpdb_read(sysdumpdb_path, (char *)(&header_g), size, 0)){
		ALOGD("read header error ,exit sysdumpdb init \n ");
		return ERR_NO_PARTION;
	}
	full_dump_flag = !!(header_g.dump_flag & AP_FULL_DUMP_ENABLE);
	set_persist_prop(full_dump_flag);
	return ret;
}
int set_dump_status(int ops_type){
	int ret = 0;
	char sysdumpdb_path[PARTITION_NAME_MAX_SIZE];
	char prop[128] = {0};
	int size = sizeof(struct dumpdb_header);
	int full_dump_flag = -1;
	int mini_dump_flag = -1;

	ALOGD("%s in\n", __func__);
	/*	Get sysdumpdb partition path	*/
	if (-1 == property_get("ro.vendor.product.partitionpath", prop, DEFAULT_PROP_VALUE)){
		ALOGD(" get partitionpath fail\n");
		return ERR_NORMAL;
	}
	snprintf(sysdumpdb_path, sizeof(sysdumpdb_path), "%s%s", prop, SYSDUMPDB_PARTITION_NAME);

	if(size != sysdumpdb_read(sysdumpdb_path, (char *)(&header_g), size, 0)){
		ALOGD("read header error ,exit sysdumpdb init \n ");
		return ERR_NO_PARTION;
	}
	switch(ops_type) {
		case FULL_DUMP_ENABLE:
			header_g.dump_flag |= AP_FULL_DUMP_ENABLE;
			break;
		case FULL_DUMP_DISENABLE:
			header_g.dump_flag &= (~AP_FULL_DUMP_ENABLE);
			break;
		case MINI_DUMP_ENABLE:
			header_g.dump_flag |= AP_MINI_DUMP_ENABLE;
			break;
		case MINI_DUMP_DISENABLE:
			header_g.dump_flag &= (~AP_MINI_DUMP_ENABLE);
			break;
		deault:
			ALOGE("%s: invalid ops type:  %d", __FUNCTION__, ops_type);
			return ERR_NORMAL;
	}
	header_g.dump_flag |= FIRST_BOOT;
	if(size != sysdumpdb_write(sysdumpdb_path, (char*)(&header_g), size, 0)){
		ALOGD("%s:write  header fail ,sysdumpdb path : %s", __FUNCTION__, sysdumpdb_path);
		return -1;
	}
	/*TODO : here ,no mini dump prop */
	full_dump_flag = !!(header_g.dump_flag & AP_FULL_DUMP_ENABLE);
	set_persist_prop(full_dump_flag);
	return ret;
}
int get_ops_type(const char *ops)
{
	int enable = -1;
	if (!strcmp(ops, "true"))
		enable = 1;
	else if (!strcmp(ops, "false"))
		enable = 0;
	else
		ALOGD(" invalid ops  : %s , do nothing  \n", ops);
	return enable;
}
/* only prop status changed means modification ops*/
int is_modify_status(void)
{
	char fulldump_prop_enable[128] = {0};
	int modify_flag = 0;
	int status = -1;

	/*	judge fulldump modification ops */
	if (-1 == property_get(DEBUG_FULLDUMP_PROP, fulldump_prop_enable, DEFAULT_PROP_VALUE)) {
		ALOGD(" get prop error : %s : %s  \n", DEBUG_FULLDUMP_PROP, fulldump_prop_enable);
		return 0;
	} else {
		ALOGD("get prop ok : %s : %s  \n", DEBUG_FULLDUMP_PROP, fulldump_prop_enable);
		status = get_ops_type(fulldump_prop_enable);
		if(-1 == status ) {
			modify_flag = 0;
			ALOGD("modify_flag : %d , need do other ops ...... \n", modify_flag);
		} else {

			if(status)
				set_dump_status(FULL_DUMP_ENABLE);
			else
				set_dump_status(FULL_DUMP_DISENABLE);
			modify_flag = 1;
			ALOGD("modify_flag : %d , do not do other ops, return  ...... \n", modify_flag);
		}
	}
	return modify_flag;
}
int main(int argc, char** argv)
{
	char prop[128] = {0};

	ALOGD("start SystemDebuggerd %d", argc);
	if(argc == 1) {

		/*	here , we handle modify dump enable status */
		if (is_modify_status())
			return 0;

		/*	Get sysdumpdb partition path	*/
		if (-1 == property_get(VERSION_INFO, prop, DEFAULT_PROP_VALUE)){
			ALOGD(" get %s fail, do not minidump_init \n", VERSION_INFO);
		} else {
			if((strstr(prop, "aosp"))!=NULL){ /* find the string line*/
				ALOGD(" %s : %s ,GSI version need minidump_init \n", VERSION_INFO, prop);
				minidump_init();
			} else {
				ALOGD(" not GSI version, no need  minidump_init \n");
			}
		}
		return do_server();
		/* set dump status according to argv[1] value */
	} else {
		ALOGE("Invalid arg , do nothing.. \n");
	}
	return 0;
}
