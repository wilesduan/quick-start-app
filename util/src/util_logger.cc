#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/ipc.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <stddef.h>
#include <map>
#include <arpa/inet.h>
#include <ctype.h>

#include <util_fcntl.h>
#include <util_file.h>
#include <sched_cpu_affinity.h>
#include "util_logger.h"
#include "time_util.h"
#include <google/protobuf/stubs/common.h> 
#include "string_tools.h"

#define K_MAX_INT_VALUE 0x7FFFFFFF
#define K_MONITOR_ACC K_MAX_INT_VALUE-1
#define K_MONITOR_FINAL K_MAX_INT_VALUE-2
#define K_MONITOR_MAX K_MAX_INT_VALUE-3
#define K_MONITOR_MIN K_MAX_INT_VALUE-4

#define ALARM_SOCK_PATH   "/var/run/lancer/collector.sock"
#define ALARM_TASK_ID     "000161"
#define ALARM_HARD_BYTES  "_ALARM]"
#define NOTICE_HARD_BYTES "#BLINK_NOTICE#"

#define K_LOG_LINE_SIZE 4096
#define K_LOG_BUFF_MAGIC 0xEFEFEFEF

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

const long int dayseconds = 24 * 60 * 60;
util_bim_logger_t* g_bim_logger = NULL;
static sockaddr_un g_alarm_addr;
static int g_sockaddr_len = 0;
static int g_alarm_addr_len = 0;

static util_log_file_info_t* g_debug_log_file = NULL;
static util_log_file_info_t* g_info_log_file = NULL;
static util_log_file_info_t* g_warn_log_file = NULL;
static util_log_file_info_t* g_error_log_file = NULL;


static time_t g_time_now = 0;
static sockaddr_in g_udp_log_server_addr;
static sockaddr_in g_monitor_server_addr;

static int open_unix_socket();
static int open_log_file();
static int open_remote_log_server(const char* remote);
static int open_sys_log();
static int open_monitor_server(const char* monitor);
static pthread_t g_logger_pid = 0;
static int g_exit_logger = 0;

static void send_alarm_to_elk(int level, char* sz_log);

static size_t get_rotate_size(json_object* js_rotate_size)
{
	if(NULL == js_rotate_size){
		return 1024*1024*1024;
	}

	const char* rotate_size = json_object_get_string(js_rotate_size); 
	size_t unit = 1;
	const char* pu = rotate_size + strlen(rotate_size)-1;
	while(pu != rotate_size && (*pu == ' ' || *pu == '\t' || *pu == '\n')){
		--pu;
	}

	if(*pu == 'G' || *pu == 'g'){
		unit = 1024*1024*1024;
	}else if(*pu == 'M' || *pu == 'm'){
		unit = 1024*1024;
	}else if(*pu == 'K' || *pu == 'k'){
		unit = 1024;
	}

	return atoi(rotate_size)*unit;
}

static void init_log_thread(util_log_thread_t* log_thread)
{
	sem_init(&(log_thread->sem), 0, 0);
	pthread_spin_init(&log_thread->spinlock, 0);
	pthread_mutex_init(&(log_thread->mutex), NULL);
	log_thread->in = 1;
	log_thread->out = 0;
}

static void pb_log_handler(::google::protobuf::LogLevel level, const char* filename, 
		int line, const std::string& message)
{
	if(level != ::google::protobuf::LOGLEVEL_ERROR || level != ::google::protobuf::LOGLEVEL_FATAL){
		return;
	}

	util_write_log(LEVEL_LOG_ERROR, filename, line, "protobuf", message.data());
}

int util_init_bim_logger(const char* appname, json_object* conf)
{
	::google::protobuf::SetLogHandler(pb_log_handler);

	g_time_now = time(NULL);
	g_bim_logger = (util_bim_logger_t*)calloc(1, sizeof(util_bim_logger_t));
	g_bim_logger->appname = (NULL==appname)?NULL:strdup(appname);

	init_log_thread(&g_bim_logger->debug_log_thread);
	init_log_thread(&g_bim_logger->info_log_thread);
	init_log_thread(&g_bim_logger->err_log_thread);
	init_log_thread(&g_bim_logger->warn_log_thread);

	int rc = open_unix_socket();
	if(rc){
		printf("failed to open unix socket\n");
		//return -1;
	}

	g_bim_logger->last_upload_time = g_time_now;

	json_object* js_level = NULL;
	json_object_object_get_ex(conf, "level", &js_level);
	g_bim_logger->log_level = (NULL == js_level)?8:json_object_get_int(js_level);

	json_object* js_local = NULL;
	json_object_object_get_ex(conf, "local", &js_local);
	g_bim_logger->local_path = (NULL == js_local)?NULL:strdup(json_object_get_string(js_local));

	json_object* js_rotate_size = NULL;
	json_object_object_get_ex(conf, "rotate_size", &js_rotate_size);
	g_bim_logger->rotate_size = get_rotate_size(js_rotate_size);

	json_object* js_rotate_interval = NULL;
	json_object_object_get_ex(conf, "rotate_interval", &js_rotate_interval);
	g_bim_logger->rotate_interval = (NULL == js_rotate_interval)?0:json_object_get_int(js_rotate_interval);

	json_object* js_keep_files = NULL;
	json_object_object_get_ex(conf, "keep_files", &js_keep_files);
	g_bim_logger->keep_files = (NULL == js_keep_files)?0:json_object_get_int(js_keep_files);


	rc = open_log_file();
	if(rc){
		printf("failed to open log file under path:%s", g_bim_logger->local_path);
		return -1;
	}

	json_object* js_remote = NULL;
	json_object_object_get_ex(conf, "remote", &js_remote);
	const char* remote = (NULL == js_remote)?NULL:json_object_get_string(js_remote);
	//udp://ip:port
	rc = open_remote_log_server(remote);
	if(rc){
		printf("failed to open remote log server\n");
		return -2;
	}

	json_object* js_syslog = NULL;
	json_object_object_get_ex(conf, "syslog", &js_syslog);
	g_bim_logger->write_sys_log = (NULL == js_syslog)?0:json_object_get_int(js_syslog);
	open_sys_log();

	json_object* js_monitor = NULL;
	json_object_object_get_ex(conf, "monitor", &js_monitor);
	const char* monitor = (NULL == js_monitor)?NULL:json_object_get_string(js_monitor);
	//udp://ip:port
	rc = open_monitor_server(monitor);
	if(rc){
		printf("failed to open monitor server\n");
		return -3;
	}

	return 0;
}

int util_logger_set_monitor_upload_cb(fn_monitor_upload_cb cb)
{
	if(NULL == g_bim_logger || 0 == g_bim_logger->monitor_udp_fd){
		printf("failed to set upload callback\n");
		return -1;
	}

	g_bim_logger->fn_updload = cb;
	return 0;
}

static void gen_unix_sockaddr(const char* sz_unix_addr, struct sockaddr_un* addr)
{
	memset(addr, 0, sizeof(sockaddr_un));
	addr->sun_family = AF_UNIX;
	strcpy(addr->sun_path, sz_unix_addr);
}

static int open_unix_socket()
{
	g_bim_logger->unix_sock_alarm_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(g_bim_logger->unix_sock_alarm_fd <= 0) {
		printf("failed to create alarm socket\n");
	}
	else
		util_fcntl(g_bim_logger->unix_sock_alarm_fd);

	char sz_unix_addr[1024];
	key_t key = ftok("./", 1);
	int len = snprintf(sz_unix_addr, sizeof(sz_unix_addr)-1, "./.%s.%d.sock", g_bim_logger->appname, key);
	sz_unix_addr[sizeof(sz_unix_addr) -1] = 0;
	unlink(sz_unix_addr);

	g_sockaddr_len = offsetof(struct sockaddr_un, sun_path) + len;
	gen_unix_sockaddr(ALARM_SOCK_PATH, &g_alarm_addr);
	g_alarm_addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(ALARM_SOCK_PATH);
	
	return 0;
}

static void remove_exceed_files(const char* type)
{
	char sz_file_pattern[1024];
	snprintf(sz_file_pattern, sizeof(sz_file_pattern)-1, "%s.%s.log", g_bim_logger->appname, type);
	sz_file_pattern[sizeof(sz_file_pattern)-1] = 0;

	DIR* dir = opendir(g_bim_logger->local_path);
	if(NULL == dir){
		return;
	}

	struct stat file_info;
	char sz_file_name[1024];
	sz_file_name[1023] = 0;
	std::map<time_t, char*> files;
	dirent* entry = NULL;
	while((entry = readdir(dir)) != NULL){
		if(strstr(entry->d_name, sz_file_pattern) != NULL){
			snprintf(sz_file_name, sizeof(sz_file_name)-1, "%s/%s", g_bim_logger->local_path, entry->d_name);
			stat(sz_file_name, &file_info);
			files[file_info.st_mtime] = strdup(sz_file_name);
		}
	}
	closedir(dir);

	if(files.size() > g_bim_logger->keep_files){
		int rm_num = files.size() - g_bim_logger->keep_files;
		for(std::map<time_t, char*>::iterator it = files.begin(); it != files.end() && rm_num >0; ++it){
			--rm_num;
			unlink(it->second);
		}
	}

	for(std::map<time_t, char*>::iterator it = files.begin(); it != files.end(); ++it){
		free(it->second);
	}
}

static int get_same_day_log_num(const char* type, time_t timestamp)
{
	char sz_file_pattern[1024];
	snprintf(sz_file_pattern, sizeof(sz_file_pattern)-1, "%s.%s.log.%s", g_bim_logger->appname, type, strtime_ymd(timestamp));
	sz_file_pattern[sizeof(sz_file_pattern)-1] = 0;

	DIR* dir = opendir(g_bim_logger->local_path);
	if(NULL == dir){
		return 0;
	}

	int idx = 0;
	dirent* entry = NULL;
	while((entry = readdir(dir)) != NULL){
		if(strstr(entry->d_name, sz_file_pattern) != NULL){
			const char* pidx = strstr(entry->d_name, "#");
			int num = atoi(pidx+1);
			if(num > idx){
				idx = num;
			}
		}
	}
	closedir(dir);

	return idx;
}

static void rotate_log_file(const char* type, FILE** fp)
{
	if(NULL == type || NULL == fp || NULL == *fp){
		return;
	}
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name)-1, "%s/%s.%s.log", g_bim_logger->local_path, g_bim_logger->appname, type);
	struct stat file_info;
    if(stat(sz_file_name, &file_info)){
		return;
	}

	int log_num = get_same_day_log_num(type, file_info.st_mtime);
	char sz_rotate_file_name[1024];
	snprintf(sz_rotate_file_name, sizeof(sz_rotate_file_name)-1, "%s/%s.%s.log.%s#%d", g_bim_logger->local_path, g_bim_logger->appname, type, strtime_ymd(file_info.st_mtime), log_num+1);
	rename(sz_file_name, sz_rotate_file_name);

	if(!fp)
		return;

	if(*fp){
		*fp = freopen(sz_file_name, "a", *fp);
	}else{
		*fp = fopen(sz_file_name, "a");
	}
}

static int offset_of_day(time_t timestamp)
{
	struct tm* ptm = localtime(&timestamp);
	int offset = ptm->tm_hour*60+ptm->tm_min;
	return offset;
}

static void prepare_log_env(const char* type)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name)-1, "%s/%s.%s.log", g_bim_logger->local_path, g_bim_logger->appname, type);
	if(access(sz_file_name, F_OK)){
		return;
	}

	struct stat file_info;
	stat(sz_file_name, &file_info);

	if(g_bim_logger->rotate_interval){
		if(!is_same_day(file_info.st_mtime, g_time_now) || 
			offset_of_day(g_time_now)/(g_bim_logger->rotate_interval) != offset_of_day(file_info.st_mtime)/(g_bim_logger->rotate_interval)){
			rotate_log_file(type, NULL);
		}
	}

	memset(&file_info, 0, sizeof(file_info));
	stat(sz_file_name, &file_info);
	if(g_bim_logger->rotate_size <= (size_t)file_info.st_size){
		rotate_log_file(type, NULL);
	}

	return;
}

static int do_open_log(const char* type, util_log_file_info_t* log_file)
{
	prepare_log_env(type);
	
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name)-1, "%s/%s.%s.log", g_bim_logger->local_path, g_bim_logger->appname, type);
	log_file->fp = fopen(sz_file_name, "a");
	if(NULL == log_file->fp){
		return -1;
	}

	struct stat file_stat;
	stat(sz_file_name, &file_stat);
	log_file->start =  g_time_now;
	log_file->size = file_stat.st_size;
	log_file->level = strdup(type);

	remove_exceed_files(type);
	return 0;
}

static int open_debug_log()
{
	if(!(g_bim_logger->log_level & LEVEL_LOG_DEBUG)){
		return 0;
	}

	g_debug_log_file = (util_log_file_info_t*)calloc(1, sizeof(util_log_file_info_t));

	return do_open_log("debug", g_debug_log_file);
}
static int open_info_log()
{
	if(!(g_bim_logger->log_level & LEVEL_LOG_INFO)){
		return 0;
	}

	g_info_log_file = (util_log_file_info_t*)calloc(1, sizeof(util_log_file_info_t));
	return do_open_log("info", g_info_log_file);
}

static int open_warn_log()
{
	if(!(g_bim_logger->log_level & LEVEL_LOG_WARN)){
		return 0;
	}

	g_warn_log_file = (util_log_file_info_t*)calloc(1, sizeof(util_log_file_info_t));
	return do_open_log("warn", g_warn_log_file);
}

static int open_error_log()
{
	if(!(g_bim_logger->log_level & LEVEL_LOG_ERROR)){
		return 0;
	}

	g_error_log_file = (util_log_file_info_t*)calloc(1, sizeof(util_log_file_info_t));
	return do_open_log("error", g_error_log_file);
}

static int open_log_file()
{
	if(NULL == g_bim_logger->local_path){
		return 0;
	}

	create_dir(g_bim_logger->local_path, 0775);
	int rc = open_debug_log();
	if(rc){
		return rc;
	}

	rc = open_info_log();
	if(rc){
		return rc;
	}

	rc = open_warn_log();
	if(rc){
		return rc;
	}

	rc = open_error_log();
	if(rc){
		return rc;
	}

	return 0;
}
//udp://ip:port
static int open_monitor_server(const char* monitor)
{
	if(NULL == monitor){
		g_bim_logger->monitor_udp_fd = 0;
		return 0;
	}

	const char* p = monitor;
	while(*p != 0 && (*p == ' ' || *p == '\t' || *p == '\n')){
		++p;
	}

	char* protocol = NULL;
	const char* addr = strstr(p, "://");
	if(addr){
		protocol = strndup(p, addr-p);
		addr += 3;
	}else{
		protocol = strdup("udp");
		addr = p;
	}

	if(strcmp(protocol, "udp") != 0){
		printf("only support udp monitor server yet:%s\n", monitor);
		free(protocol);
		return -1;
	}

	free(protocol);
	const char* port = strstr(addr, ":");
	if(NULL == port){
		printf("monitor server miss port:%s\n", monitor);
		return -2;
	}

	char* ip = strndup(addr, port - addr);
	memset(&g_monitor_server_addr, 0, sizeof(g_monitor_server_addr));
	g_monitor_server_addr.sin_family = AF_INET;
	if(inet_pton(AF_INET, ip, &(g_monitor_server_addr.sin_addr)) <=0){
		free(ip);
		printf("invalid monitor server ip:%s\n", monitor);
		return -3;
	}
	free(ip);

	int u_port = atoi(port+1);
	if(u_port <= 0){
		printf("invalid monitor server port:%s\n", monitor);
		return -4;
	}

	g_monitor_server_addr.sin_port = htons(u_port);
	g_bim_logger->monitor_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(g_bim_logger->monitor_udp_fd<= 0){
		printf("failed to create monitor upd fd:%s\n", monitor);
		return -5;
	}
//	util_fcntl(g_bim_logger->monitor_udp_fd);

	return 0;
}
//udp://ip:port
static int open_remote_log_server(const char* remote)
{
	if(NULL == remote){
		g_bim_logger->remote_udp_fd = 0;
		return 0;
	}


	const char* p = remote;
	while(*p != 0 && (*p == ' ' || *p == '\t' || *p == '\n')){
		++p;
	}

	char* protocol = NULL;
	const char* addr = strstr(p, "://");
	if(addr){
		protocol = strndup(p, addr-p);
		addr += 3;
	}else{
		protocol = strdup("udp");
		addr = p;
	}

	if(strcmp(protocol, "udp") != 0){
		printf("only support udp log server yet:%s\n", remote);
		free(protocol);
		return -1;
	}

	free(protocol);
	const char* port = strstr(addr, ":");
	if(NULL == port){
		printf("udp log server miss port:%s\n", remote);
		return -2;
	}

	char* ip = strndup(addr, port - addr);
	memset(&g_udp_log_server_addr, 0, sizeof(g_udp_log_server_addr));
	g_udp_log_server_addr.sin_family = AF_INET;
	if(inet_pton(AF_INET, ip, &(g_udp_log_server_addr.sin_addr)) <=0){
		free(ip);
		printf("invalid udp log server ip:%s\n", remote);
		return -3;
	}
	free(ip);

	int u_port = atoi(port+1);
	if(u_port <= 0){
		printf("invalid udp log server port:%s\n", remote);
		return -4;
	}

	g_udp_log_server_addr.sin_port = htons(u_port);
	g_bim_logger->remote_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(g_bim_logger->remote_udp_fd <= 0){
		printf("failed to create udp log fd:%s\n", remote);
		return -5;
	}
	util_fcntl(g_bim_logger->remote_udp_fd);

	return 0;
}

static int open_sys_log()
{
	if(!g_bim_logger->write_sys_log){
		return 0;
	}

	openlog(g_bim_logger->appname, 0, LOG_USER);
	return 0;
}

#if 0
static const char* upper_level(const char* level)
{
	static char sz_level[10];
	int i = 0;
	const char* p = level;
	while(*p!=0){
		sz_level[i++] = toupper(*p);
	}

	sz_level[i] = 0;
	return sz_level;
}
#endif

static bool need_rotate_log(util_log_file_info_t* log_file)
{
	if(g_bim_logger->rotate_interval && 
			(!is_same_day(log_file->start, g_time_now) || 
			 (offset_of_day(log_file->start)/(g_bim_logger->rotate_interval) != offset_of_day(g_time_now)/(g_bim_logger->rotate_interval))
			 )
	  ){
		return true;
	}

	if(g_bim_logger->rotate_size <= log_file->size){
		return true;
	}
	return false;
}

static void do_write_local_log(util_log_file_info_t* log_file, const char* buff, size_t size)
{
	if(NULL == log_file || NULL == log_file->fp){
		printf("cannot open local file:%s\n", buff);
		return;
	}

	if(need_rotate_log(log_file)){
		rotate_log_file(log_file->level, &(log_file->fp));
		log_file->start = g_time_now;
		log_file->size = 0;

		if(NULL == log_file || NULL == log_file->fp){
			return;
		}

		remove_exceed_files(log_file->level);
	}

	fprintf(log_file->fp, "%s:%s", log_file->level, buff+2);
	if(buff[size-1] != '\n'){
		fprintf(log_file->fp, "\n");
	}
	fflush(log_file->fp);
	log_file->size += (size + 1 + strlen(log_file->level));
}

static void write_local_log(int level, const char* buff, size_t size)
{
	switch(level){
		case LEVEL_LOG_DEBUG:
		case LEVEL_LOG_ANY:
			do_write_local_log(g_debug_log_file, buff, size);
			break;
		case LEVEL_LOG_INFO:
			do_write_local_log(g_info_log_file, buff, size);
			break;
		case LEVEL_LOG_WARN:
			do_write_local_log(g_warn_log_file, buff, size);
			break;
		case LEVEL_LOG_ERROR:
			do_write_local_log(g_error_log_file, buff, size);
			break;
		default:
			break;
	}
}

static void write_udp_log(int level, const char* buff, size_t size)
{
	sendto(g_bim_logger->remote_udp_fd, buff, size, 0, (struct sockaddr*)&g_udp_log_server_addr, sizeof(g_udp_log_server_addr));
}

static int get_syslog_lvl(int level)
{
	switch(level){
		case LEVEL_LOG_DEBUG:
			return LOG_DEBUG;
		case LEVEL_LOG_INFO:
			return LOG_INFO;
		case LEVEL_LOG_WARN:
			return LOG_WARNING;
		case LEVEL_LOG_ERROR:
			return LOG_ERR;
	}
	return LOG_ERR;
}

#if 0
static void write_sys_log(int level, const char* buff, size_t size)
{
	return;
	//int syslog_lvl = get_syslog_lvl(level);
	//syslog(LOG_USER|syslog_lvl, "%s", buff);
}
#endif

static void flush_log(util_log_thread_t* log_thread, int level, const char* buff, size_t size)
{
	if(!(level & g_bim_logger->log_level)){
		return;
	}

	if(g_bim_logger->local_path){
		write_local_log(level, buff, size);
	}

	if(g_bim_logger->remote_udp_fd > 0){
		write_udp_log(level, buff, size);
	}

	if(g_bim_logger->write_sys_log){
		//write_sys_log(level, buff, size);
	}
}

static void* util_logger_routine(void* arg)
{
	//set_sched_cpu_affinity();

	if(NULL == g_bim_logger){
		return NULL;
	}

	util_log_thread_t* log_thread = (util_log_thread_t*)arg;
	int level = 0;
	while(!g_exit_logger){
		sem_wait(&log_thread->sem);
		//pthread_spin_lock(&log_thread->spinlock);
		pthread_mutex_lock(&log_thread->mutex);
		uint64_t idx = (++log_thread->out) &(K_MAX_UTIL_LOGS-1);
		util_log_t* log = log_thread->logs[idx];
		log_thread->out = idx;
		pthread_mutex_unlock(&log_thread->mutex);
		//pthread_spin_unlock(&log_thread->spinlock);

		if(!log || log->magic != (int)K_LOG_BUFF_MAGIC){
			continue;
		}

		struct tm m;
		struct tm* pTm = localtime_r(&log->ts, &m);
		if(!pTm){
			continue;
		}
		int cnt = 2;
		unsigned len = 0;
		unsigned log_len = log->len;
		log_len = log_len>K_LOG_LINE_SIZE?K_LOG_LINE_SIZE:log_len;
		while(len < 32 && len < log_len && cnt){
			if(log->content[len++] == ':'){
				--cnt;
			}
		}
		int lk = sprintf(log->content+len, "%d-%02d-%02d %02d:%02d:%02d",  pTm->tm_year+1900,  pTm->tm_mon + 1, pTm->tm_mday, pTm->tm_hour, pTm->tm_min, pTm->tm_sec);
		log->content[lk+len] = ':';
		g_time_now = time(NULL);
		level = log->level;
		flush_log(log_thread, level, log->content, log_len);

		if(g_bim_logger->write_sys_log){
			int syslog_lvl = get_syslog_lvl(level);
			syslog(LOG_USER|syslog_lvl, "%s", log->content);
		}

		if(log->log_2_elk){
			send_alarm_to_elk(level, log->content);
		}
	}

	return NULL;
}

void util_run_logger()
{
	if(NULL == g_bim_logger){
		return;
	}

	pthread_create(&(g_bim_logger->debug_log_thread.pid), NULL, util_logger_routine, &(g_bim_logger->debug_log_thread));
	pthread_create(&(g_bim_logger->info_log_thread.pid), NULL, util_logger_routine, &(g_bim_logger->info_log_thread));
	pthread_create(&(g_bim_logger->err_log_thread.pid), NULL, util_logger_routine, &(g_bim_logger->err_log_thread));
	pthread_create(&(g_bim_logger->warn_log_thread.pid), NULL, util_logger_routine, &(g_bim_logger->warn_log_thread));
}

void util_stop_logger()
{
	g_exit_logger = 1;
	pthread_cancel(g_logger_pid);
	pthread_join(g_logger_pid, NULL);
}

static bool check_logging_2_elk(en_log_level level, const char* fmt)
{
	if(g_bim_logger->unix_sock_alarm_fd > 0) {
		if((level == LEVEL_LOG_ERROR && fmt[0] == '[' && strstr(fmt, ALARM_HARD_BYTES))
			|| (level == LEVEL_LOG_INFO && !strncmp(fmt, NOTICE_HARD_BYTES, strlen(NOTICE_HARD_BYTES)))
			|| (level == LEVEL_LOG_INFO && strstr(fmt, "ev_name") != NULL)) {
			return true;
		}
	}
	return false;
}


static void add_log_content_2_log_routine(util_log_t* log)
{
	util_log_thread_t* log_thread = NULL;
	switch(log->level){
		case LEVEL_LOG_DEBUG:
			log_thread = &g_bim_logger->debug_log_thread;
			break;
		case LEVEL_LOG_INFO:
			log_thread = &g_bim_logger->info_log_thread;
			break;
		case LEVEL_LOG_ERROR:
			log_thread = &g_bim_logger->err_log_thread;
			break;
		case LEVEL_LOG_WARN:
			log_thread = &g_bim_logger->warn_log_thread;
			break;
		default:
			break;
	}

	if(!log_thread){
		return;
	}

	if(log_thread->out == log_thread->in){
		//buff full
		return;
	}

	int post = 0;
	//pthread_spin_lock(&log_thread->spinlock);
	pthread_mutex_lock(&log_thread->mutex);
	if(likely(log_thread->out != log_thread->in)){
		log_thread->logs[(log_thread->in)++] = log;
		log_thread->in = (log_thread->in) & (K_MAX_UTIL_LOGS-1);
		post = 1;
	}
	pthread_mutex_unlock(&log_thread->mutex);
	//pthread_spin_unlock(&log_thread->spinlock);
	if(post)
		sem_post(&log_thread->sem);
}

static util_log_buffs_t* calloc_log_buffs()
{
	util_log_buffs_t* buff = (util_log_buffs_t*)calloc(1, sizeof(util_log_buffs_t));
	return buff;
}

static util_log_buff_t* get_log_buff(en_log_level level, util_log_buffs_t* buffs)
{
	switch(level){
		case LEVEL_LOG_DEBUG:
			 return &buffs->debug;
		case LEVEL_LOG_INFO:
			 return &buffs->info;
		case LEVEL_LOG_ERROR:
			 return  &buffs->err;
		case LEVEL_LOG_WARN:
			return &buffs->warn;
		default:
			break;
	}

	return NULL;
}

#define K_LOG_BUFF_SIZE 4194304
static util_log_t* get_next_write_log(util_log_buff_t* buff)
{
	if(!buff->buff){
		buff->buff = (char*)malloc(K_LOG_BUFF_SIZE);
	}

	if(buff->next+K_LOG_LINE_SIZE > K_LOG_BUFF_SIZE){
		buff->next = 0;
	}

	util_log_t* log = (util_log_t*)(buff->buff+buff->next);
	log->magic = K_LOG_BUFF_MAGIC;
	return log;
}

void util_write_log(en_log_level level, const char* file, int line_num, const char* function, const char* fmt, ...)
{
	static __thread util_log_buffs_t* buffs = calloc_log_buffs();

	long int tid = gettid();
	if(!g_bim_logger){
		printf("%ld %s %d %s ", tid, file, line_num, function);
		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		printf("\n");
		return;
	}

	if(!(level & g_bim_logger->log_level)){
		return;
	}

	util_log_buff_t* buff = get_log_buff(level, buffs);
	if(!buff){
		return;
	}

	util_log_t* log = get_next_write_log(buff);
	log->ts = time(NULL);
	int len = snprintf(log->content, K_LOG_LINE_SIZE - sizeof(util_log_t)-1, "%d:%ld:xxxx-xx-xx xx:xx:xx:%s:%d:%s|", level, tid, file, line_num, function);
	va_list args;
	va_start(args, fmt);
	len += vsnprintf(log->content+len, K_LOG_LINE_SIZE-sizeof(util_log_t)-len-1, fmt, args);
	va_end(args);
	if(len > (int)(K_LOG_LINE_SIZE - sizeof(util_log_t)-1)){
		len = K_LOG_LINE_SIZE - sizeof(util_log_t)-1;
	}
	log->content[len] = 0;
	log->len = len+1;
	log->level = level;
	log->log_2_elk = check_logging_2_elk(level, fmt);
	buff->next = buff->next + len + sizeof(util_log_t);
	add_log_content_2_log_routine(log);
	return;
}

static void send_alarm_to_elk(int level, char* sz_log)
{
	json_object* root = json_object_new_object();

	int code = 0;
	char trace_id[128] = {0};
	char module[32] = {0};
	uint64_t uid = 0;
	if(level == LEVEL_LOG_ERROR) {
		char alarm_type[32] = {0};
		int detail_offset = 0;
		switch(sscanf(sz_log, "%*[^[][%31[^[][%31[^]]]@%n%*[^,],%*[^:]:%127[^, ]%*[^:]:%19lu", module, alarm_type, &detail_offset, trace_id, &uid)) {
			case 4:
				json_object_object_add(root, "uid", json_object_new_int64(uid));
				// fall-through
			case 3:
				json_object_object_add(root, "trace_id", json_object_new_string(trace_id));
				// fall-through
				if(!strncmp(sz_log + detail_offset, "call", 4)) {
					sscanf(sz_log + detail_offset, "%*[^.].%*[^:]:%9d", &code);
					json_object_object_add(root, "code", json_object_new_int(code));
				}
				else if(!strncmp(sz_log + detail_offset, "return", 6)) {
					sscanf(sz_log + detail_offset, "%*[^:]:%9d", &code);
					json_object_object_add(root, "code", json_object_new_int(code));
				}
				// fall-through
			case 2:
				if(detail_offset)
					json_object_object_add(root, "details", json_object_new_string(sz_log + detail_offset));
				json_object_object_add(root, "alarm_type", json_object_new_string(alarm_type));
				// fall-through
			case 1:
				if(strstr(module, ALARM_HARD_BYTES) != 0)
					module[strlen(module) - strlen(ALARM_HARD_BYTES)] = '\0';
				json_object_object_add(root, "module", json_object_new_string(module));
				break;
			default:
				json_object_object_add(root, "log", json_object_new_string(sz_log));
		}
	}
	else if(level == LEVEL_LOG_INFO) {

		char* ev_start = strstr(sz_log, "ev_name");
		if (ev_start != NULL)//如果字符串中有ev_name则走事件上报
		{
			std::vector<std::string> field_values;
			implode(ev_start, "|", field_values);
			for (size_t i = 0; i < field_values.size(); ++i)
			{
				std::vector<std::string> field_value;	
				implode(field_values[i], ":", field_value);
				if (field_value.size() == 2)
				{
					int64_t i_val = 0;
					double d_val = 0.0;
					json_object* p_obj = NULL;
					switch (parse_num(field_value[1].c_str(), i_val, d_val))
					{
					case 0:
						p_obj = json_object_new_int64(i_val);
						break;
					case 1:
						p_obj = json_object_new_double(d_val);
						break;
					default:	
						p_obj = json_object_new_string(field_value[1].c_str());
						break;
					}
					
					json_object_object_add(root, field_value[0].c_str(), p_obj);
				}
			}
			
			util_send_to_elk(level, "event", root);
			json_object_put(root);
			
			return;
		}
		
		unsigned int cost = 0;
		char method[32] = {0};
		int params_offset = 0;
		char sz_buffer[0x100] = {0};

		switch(sscanf(sz_log, "%*[^[][%31[^@]@%31[^|]|%127[^|]|%9ums|%9d|%19lu|%*[^|]|%*[^[]%n",
			module, method, trace_id, &cost, &code, &uid, &params_offset)) {
			case 6:
				if(params_offset)
					json_object_object_add(root, "params", json_object_new_string(sz_log + params_offset));
				json_object_object_add(root, "uid", json_object_new_int64(uid));
				// fall-through
			case 5:
				json_object_object_add(root, "code", json_object_new_int(code));
				// fall-through
			case 4:
				json_object_object_add(root, "cost", json_object_new_int(cost));
				// fall-through
			case 3:
				json_object_object_add(root, "trace_id", json_object_new_string(trace_id));
				// fall-through
			case 2:
				snprintf(sz_buffer, sizeof(sz_buffer) - 1, "%s.%s", module, method);
				json_object_object_add(root, "cmd", json_object_new_string(sz_buffer));
				break;
			default:
				json_object_object_add(root, "log", json_object_new_string(sz_log));
		}
	}

	util_send_to_elk(level, (level == LEVEL_LOG_ERROR ? "alarm" : "access"), root);
	if(root) json_object_put(root);
}

void util_send_to_elk(int level, const char* type, json_object* root)
{
	if(!type || !root)
		return;

	struct timeval now;
	gettimeofday(&now, NULL);

	char sz_buffer[0x100] = {0};
	sz_buffer[strftime(sz_buffer, sizeof(sz_buffer) - 1, "%FT%TZ", gmtime(&now.tv_sec))] = '\0';
	json_object_object_add(root, "time", json_object_new_string(sz_buffer));

	json_object_object_add(root, "level", json_object_new_string(level == LEVEL_LOG_ERROR ? "ERROR" : "INFO"));

	snprintf(sz_buffer, sizeof(sz_buffer) - 1, "bplus-%s-%s", type, g_bim_logger->appname);
	json_object_object_add(root, "app_id", json_object_new_string(sz_buffer));

	if(!gethostname(sz_buffer, sizeof(sz_buffer) - 1))
		json_object_object_add(root, "instance_id", json_object_new_string(sz_buffer));
	else
		json_object_object_add(root, "instance_id", json_object_new_string("UNKNOWN"));

	// use writev instead of sendto to avoid memory alloc and length limitations
	struct iovec v[2];
	v[0].iov_base = sz_buffer;
	v[0].iov_len = snprintf(sz_buffer, sizeof(sz_buffer) - 1, ALARM_TASK_ID "%ld", now.tv_sec * 1000 + now.tv_usec / 1000);
	v[1].iov_base = (void*)json_object_to_json_string(root);
	v[1].iov_len = strlen((const char*)v[1].iov_base);

	if (0 == connect(g_bim_logger->unix_sock_alarm_fd, (struct sockaddr*)&g_alarm_addr, g_alarm_addr_len)) {
		writev(g_bim_logger->unix_sock_alarm_fd, v, 2);
	}
}

int util_get_log_level()
{
	if(!g_bim_logger) return 0;
	return g_bim_logger->log_level;
}

static void write_monitor(int type, const char* key, int value)
{
	//util_write_log(LEVEL_LOG_INFO, __FILE__, __LINE__, __FUNCTION__, "write monitor. type:%d key:%s value:%d", type, key, value);
	static __thread util_tid_monitor_t* monitor = new util_tid_monitor_t();
	if(!g_bim_logger || !g_bim_logger->monitor_udp_fd || !g_bim_logger->fn_updload){
		return;
	}


	time_t now = time(NULL);
	std::map<std::string, int>& m_monitor = *(monitor->monitor);
	if(g_bim_logger->fn_updload && now - monitor->last_upload >= 10){
		(g_bim_logger->fn_updload)(g_bim_logger->monitor_udp_fd, (struct sockaddr*)&g_monitor_server_addr, sizeof(g_monitor_server_addr), g_bim_logger->appname, m_monitor);
		m_monitor.clear();
		monitor->last_upload = now;
	}

	std::string strkey(key);
	switch(type){
		case K_MONITOR_ACC:
			{
				std::map<std::string, int>::iterator it = m_monitor.find(strkey);
				if(it == m_monitor.end()){
					m_monitor.insert(std::pair<std::string, int>(strkey, value));
				}else{
					it->second += value;
				}
			}
			break;
		case K_MONITOR_FINAL:
		case K_MONITOR_MAX:
			{
				std::map<std::string, int>::iterator it = m_monitor.find(strkey);
				if(it == m_monitor.end()){
					m_monitor.insert(std::pair<std::string, int>(strkey, value));
				}else{
					int v = it->second;
					if(v < value)
						it->second = value;
				}
			}
			break;
		case K_MONITOR_MIN:
			{
				std::map<std::string, int>::iterator it = m_monitor.find(strkey);
				if(it == m_monitor.end()){
					m_monitor.insert(std::pair<std::string, int>(strkey, value));
				}else{
					int v = it->second;
					if(v < value)
						it->second = value;
				}
			}
			break;
		default:
			break;
	}
}

void util_monitor_acc(const char* key, int value)
{
	if(!g_bim_logger)
		return;
	write_monitor(K_MONITOR_ACC, key, value);
}

void util_monitor_final(const char* key, int value)
{
	if(!g_bim_logger)
		return;
	write_monitor(K_MONITOR_FINAL, key, value);
}

void util_monitor_max(const char* key, int value)
{
	if(!g_bim_logger)
		return;
	write_monitor(K_MONITOR_MAX, key, value);
}

void util_monitor_min(const char* key, int value)
{
	if(!g_bim_logger)
		return;
	write_monitor(K_MONITOR_MIN, key, value);
}

