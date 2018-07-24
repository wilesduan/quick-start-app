#ifndef _BILI_IM_UTIL_LOGGER_H_
#define _BILI_IM_UTIL_LOGGER_H_

#include <semaphore.h>
#include <stdio.h>
#include <string>
#include <time.h>
#include <map>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>  
#include <list.h>

#include <json.h>

#define K_MON_NOOP "k_LoGgEr_NoOp"
#define gettid() syscall(__NR_gettid)  
enum en_log_level 
{
	LEVEL_LOG_DEBUG = 0x01,
	LEVEL_LOG_INFO  = 0x02,
	LEVEL_LOG_WARN  = 0x04,
	LEVEL_LOG_ERROR = 0x08,
	LEVEL_LOG_ANY   = 0x0F,
};

typedef int(*fn_monitor_upload_cb)(int udp_fd, const struct sockaddr *dest_addr, socklen_t addrlen, const char* service, const std::map<std::string, int>& monitor_infos);

struct util_log_t;
#define K_MAX_UTIL_LOGS 1048576 
typedef struct util_log_thread_t
{
	sem_t sem;
	pthread_t pid;

	pthread_spinlock_t spinlock;
	pthread_mutex_t mutex;
	util_log_t* logs[K_MAX_UTIL_LOGS];
	uint64_t in;
	uint64_t out;

}util_log_thread_t;

typedef struct util_bim_logger_t
{
	int log_level;
	char* appname;

	util_log_thread_t debug_log_thread;
	util_log_thread_t info_log_thread;
	util_log_thread_t err_log_thread;
	util_log_thread_t warn_log_thread;

	int unix_sock_alarm_fd;

	char* local_path;
	size_t rotate_size;
	size_t rotate_interval;
	size_t keep_files;

	int remote_udp_fd;
	int write_sys_log;

	int monitor_udp_fd;
	fn_monitor_upload_cb fn_updload;
	time_t last_upload_time;
}util_bim_logger_t;

typedef struct util_log_file_info_t
{
	FILE* fp;
	char* level;
	time_t start;
	size_t size;
}util_log_file_info_t;

struct util_log_buff_t;
typedef struct util_log_t
{
	int magic;
	unsigned len;
	time_t ts;
	char level;
	char log_2_elk;
	char content[1];
}util_log_t;

typedef struct util_log_buff_t
{
	char* buff;
	size_t next;
}util_log_buff_t;

typedef struct util_log_buffs_t
{
	util_log_buff_t debug;
	util_log_buff_t info;
	util_log_buff_t err;
	util_log_buff_t warn;
}util_log_buffs_t;

typedef struct util_tid_monitor_t
{
	time_t last_upload;
	std::map<std::string, int>* monitor;

	util_tid_monitor_t(){
		last_upload = time(NULL);
		monitor = new std::map<std::string, int>();
	}
}util_tid_monitor_t;

int util_init_bim_logger(const char* appname, json_object* conf);
int util_logger_set_monitor_upload_cb(fn_monitor_upload_cb cb);
void util_run_logger();
void util_stop_logger();
int util_get_log_level();

void util_send_to_elk(int level, const char* type, json_object* root);

void util_write_log(en_log_level level, const char* file, int line_num, const char* funciton, const char* fmt, ...);

void util_monitor_acc(const char* key, int value);
void util_monitor_final(const char* key, int value);
void util_monitor_max(const char* key, int value);
void util_monitor_min(const char* key, int value);
#endif //_BILI_IM_UTIL_LOGGER_H_

