#include <server.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ctype.h>
#include <sys/epoll.h>
#include <monitor_func.h>
#include <kafka.h>
#include <http_client.h>

#include <algorithm>

#include <bim_util.h>
#include <co_routine.h>
#include <bim_util.h>
#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper.jute.h>
#include <zk_adaptor.h>

#include <sys/time.h>

#include <swoole_def.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

static int init_wt(worker_thread_t* wt, json_object* config);
static void init_logger(json_object* conf);
static void init_limitation();
static int init_server(server_t* server);
static int init_worker_threads(server_t* server);

static int run_as_daemon(server_t* server);
static void run_child(server_t* server);

static int do_recv_signal(void* arg);
static void do_recv_quit_signal(server_t* arg);
static void do_recv_term_signal(server_t* arg);
static void do_recv_reload_signal(server_t* arg);

static void* run_worker(void* arg);
static void stop_server(server_t* server);

static void write_pid_file(int pid);
static const char* get_pid_file();

static char g_sz_cfg[1024];
char* g_app_name = NULL;
static int g_pid_file = 0;

char g_ip[24] = {0};

int g_svr_exit = 0;
char g_start_time[128];
int g_exit_status = 0;
extern int g_sync_call_redis;
extern int g_stop_zk_thread;
int g_log_trace_point = 0;

void usage(char* app)
{
	printf("%s -f conf.json\n", app);
	exit(0);
}

static void parse_argv(int argc, char** argv)
{
	g_app_name = basename(argv[0]);
	snprintf(g_sz_cfg, sizeof(g_sz_cfg)-1, "./conf/%s.json", g_app_name);
	int c = 0;
	while(-1 != (c = getopt(argc, argv, 
				 "f:"//config file
				 "h"//show help
		))){
		switch(c){
			case 'f':
				{
					snprintf(g_sz_cfg, sizeof(g_sz_cfg)-1,"%s", optarg);
					break;
				}
			case 'h':
				{
					usage(argv[0]);
					break;
				}
			default:
				{
					break;
				}
		}
	}

	g_sz_cfg[sizeof(g_sz_cfg)-1] = 0;
}

server_t* malloc_server(int argc, char** argv)
{
	zoo_set_debug_level(ZOO_LOG_LEVEL_WARN); 
	parse_argv(argc, argv);
	char* cfg = g_sz_cfg;


	json_object* conf = load_cfg(cfg);
	if(NULL == conf){
		printf("failed to load config:%s\n", cfg);
		return NULL;
	}

	server_t* server = (server_t*)calloc(1, sizeof(server_t));
	if(NULL == server){
		printf("failed to calloc server\n");
		json_object_put(conf);
		return NULL;
	}

	server->config = conf;
	server->mt_fns.do_recv_quit_signal = do_recv_quit_signal;
	server->mt_fns.do_recv_term_signal = do_recv_term_signal;
	server->mt_fns.do_recv_reload_signal = do_recv_reload_signal;

	INIT_LIST_HEAD(&(server->routines));
	INIT_LIST_HEAD(&(server->services));
	INIT_LIST_HEAD(&(server->listens));
	INIT_LIST_HEAD(&(server->kafka_consumers));
	INIT_LIST_HEAD(&(server->kafka_producers));

	server->num_connectors = 5;
	server->async_connectors = (async_connector_t*)calloc(server->num_connectors, sizeof(async_connector_t));
	return server;
}

static void do_signal(int signum)
{
	switch(signum){
		case SIGTERM:
		case SIGQUIT:
			g_svr_exit = 1;
			break;
		default:
			break;
	}

	//printf("recv term signal\n");
}

static void add_signal_fd(server_t* server)
{
	signal(SIGTERM, do_signal);
	signal(SIGQUIT, do_signal);
	signal(SIGUSR1, do_signal);

	/*
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGUSR1);
	if(sigprocmask(SIG_BLOCK, &mask, NULL) == -1){
		perror("sigprocmask");
		return;
	}

	server->sgfd = signalfd(-1, &mask, 0);
	ev_ptr_t* ptr = (ev_ptr_t*)calloc(1, sizeof(ev_ptr_t));
	ptr->fd = server->sgfd;
	ptr->do_read_ev = do_recv_signal;
	ptr->arg = server;

	add_read_ev(server->epoll_fd, ptr);
	*/
}

static int init_server(server_t* server)
{
	json_object* sched_aff = NULL;
	json_object_object_get_ex(server->config, "sched", &sched_aff);
	if(sched_aff && json_object_get_int(sched_aff)){
		init_sched_cpu_affinity();
	}
	json_object* sync_call_redis = NULL;
	json_object_object_get_ex(server->config, "sync_redis", &sync_call_redis);
	if(sync_call_redis){
		g_sync_call_redis = json_object_get_int(sync_call_redis);
	}

	json_object* log_conf = NULL;
	json_object_object_get_ex(server->config, "log", &log_conf);
	json_object* local_name = NULL;
	json_object_object_get_ex(server->config, "name", &local_name);
	if(local_name){
		const char* name = json_object_get_string(local_name);
		if(name && strlen(name)){
			g_app_name = strdup(name);
		}
	}

	json_object* trace = NULL;
	json_object_object_get_ex(server->config, "trace", &trace);
	g_log_trace_point = trace?json_object_get_int(trace):0;

	init_logger(log_conf);
	util_run_logger();

	json_object* lancer_conf = NULL;
	json_object_object_get_ex(server->config, "lancer", &lancer_conf);
	util_init_lancer(lancer_conf?json_object_get_string(lancer_conf):NULL);


	srandom(time(NULL));
	init_limitation();

	server->appname = g_app_name;

	json_object* max_conns = NULL;
	json_object_object_get_ex(server->config, "max_conns_per_worker", &max_conns);
	server->max_conns_per_worker = max_conns?json_object_get_int(max_conns):10000;

	/*****i don't know why:if no the following lines signalfd *******/
	signal(SIGTERM, do_signal);
	signal(SIGQUIT, do_signal);
	signal(SIGUSR1, do_signal);
	signal(SIGPIPE,SIG_IGN);

	server->epoll_fd = epoll_create(1024);
	run_async_connector(server);
	
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGUSR1);
	if(sigprocmask(SIG_BLOCK, &mask, NULL) == -1){
		perror("sigprocmask");
	}

	server->sgfd = signalfd(-1, &mask, 0);

	ev_ptr_t* ptr = (ev_ptr_t*)calloc(1, sizeof(ev_ptr_t));
	ptr->fd = server->sgfd;
	ptr->do_read_ev = do_recv_signal;
	ptr->arg = server;

	add_read_ev(server->epoll_fd, ptr);

	int rc = do_listen(server);
	if(rc){
		return rc; 
	}

	rc = init_kafka_consumer(server);
	if(rc){
		printf("failed to init kafka consumer\n");
		return rc;
	}

	rc = init_kafka_producer(server);
	if(rc){
		printf("failed to init kafka producer\n");
		return rc;
	}

	rc = init_worker_threads(server);
	if(rc){
		printf("failed to init worker\n");
		return rc;
	}


	return rc;
}

static int init_worker_threads(server_t* server)
{
	json_object* wt_num = NULL;
	json_object_object_get_ex(server->config, "wt_num", &wt_num);
	server->num_worker = NULL == wt_num?10:json_object_get_int(wt_num);
	server->array_worker = (worker_thread_t*)calloc(server->num_worker, sizeof(worker_thread_t));
	for(int i = 0; i < server->num_worker; ++i){
		worker_thread_t* worker = server->array_worker + i;
		worker->mt = server;
		worker->idx = i;
		memcpy(&worker->wt_fns, &(server->wt_fns), sizeof(wt_call_backs_t));
		init_wt(worker, server->config);
		worker->next = worker+1;
	}

	server->array_worker[(server->num_worker-1)].next = server->array_worker;

	int k = 0;
	list_head* lt = NULL;
	list_for_each(lt, &(server->listens)){
		listen_t* lit = list_entry(lt, listen_t, list);
		worker_thread_t* worker = server->array_worker + (k%(server->num_worker));
		INIT_LIST_HEAD(&(lit->worker));
		list_add(&(lit->worker), &(worker->listens));
		lit->accept_worker = worker;
		++k;
	}

	return 0;
}

void add_mt_call_backs(server_t* server, mt_call_backs_t mt_fns)
{
	if(NULL == server)
		return;

	if(mt_fns.do_special_init){
		server->mt_fns.do_special_init = mt_fns.do_special_init;
	}

	if(mt_fns.do_before_run){
		server->mt_fns.do_before_run = mt_fns.do_before_run;
	}

	if(mt_fns.do_after_stop){
		server->mt_fns.do_after_stop = mt_fns.do_after_stop;
	}

	if(mt_fns.do_recv_quit_signal){
		server->mt_fns.do_recv_quit_signal = mt_fns.do_recv_quit_signal;
	}

	if(mt_fns.do_recv_term_signal){
		server->mt_fns.do_recv_term_signal = mt_fns.do_recv_term_signal;
	}

	if(mt_fns.do_recv_reload_signal){
		server->mt_fns.do_recv_reload_signal = mt_fns.do_recv_reload_signal;
	}

	if(mt_fns.do_process_udp_data){
		server->mt_fns.do_process_udp_data = mt_fns.do_process_udp_data;
	}

	if(mt_fns.do_process_http_data){
		server->mt_fns.do_process_http_data = mt_fns.do_process_http_data;
	}
}

void add_wt_call_backs(server_t* server, wt_call_backs_t wt_fns)
{
	if(NULL == server)
		return;

	memcpy(&server->wt_fns, &wt_fns, sizeof(wt_call_backs_t));

	/*
	for(int i = 0; i < server->num_worker; ++i){
		worker_thread_t* worker = server->array_worker+i;

		if(wt_fns.do_shutdown_conn){
			worker->wt_fns.do_shutdown_conn = wt_fns.do_shutdown_conn;
		}

		if(wt_fns.do_accept_conn){
			worker->wt_fns.do_accept_conn = wt_fns.do_accept_conn;
		}

		if(wt_fns.do_alloc_data){
			worker->wt_fns.do_alloc_data = wt_fns.do_alloc_data;
		}
		if(wt_fns.do_recv_notify){
			worker->wt_fns.do_recv_notify = wt_fns.do_recv_notify;
		}
	}
	*/
}

void add_routine(server_t* server, fn_pthread_routine routine, void* arg)
{
	if(NULL == server)
		return;

	pthread_routine_t* r = (pthread_routine_t*)calloc(1, sizeof(pthread_routine_t));
	if(NULL == r){
		LOG_ERR("failed to calloc routine");
		return;
	}

	INIT_LIST_HEAD(&(r->list));
	r->routine = routine;
	r->arg = arg;
	list_add(&(r->list), &(server->routines));
}

void add_service(server_t* server, service_t* service)
{
	if(NULL == server)
		return;

	INIT_LIST_HEAD(&(service->list));
	list_add(&(service->list), &(server->services));
}

int run_server(server_t* server)
{
	json_object* obj = NULL;
	json_object_object_get_ex(server->config, "daemon", &obj);
	int daemon = (NULL == obj)?0:json_object_get_int(obj);
	if(daemon){
		return run_as_daemon(server);
	}

	run_child(server);
	return 0;
}

static float get_cpu_usage(struct rusage* pre_usage, int who)
{
	struct rusage usage;
	getrusage(who, &usage);
	long int total_time = (usage.ru_utime.tv_sec*1000+usage.ru_utime.tv_usec/1000+usage.ru_stime.tv_sec*1000+usage.ru_stime.tv_usec/1000) - (pre_usage->ru_utime.tv_sec*1000+pre_usage->ru_utime.tv_usec/1000+pre_usage->ru_stime.tv_sec*1000+pre_usage->ru_stime.tv_usec/1000);
	float cpu_usage = (1.0*total_time)/100;
	memcpy(pre_usage, &usage, sizeof(usage));
	return cpu_usage;
}

static void log_server_stat(server_t* server)
{
	list_head* p;
	list_for_each(p, &server->listens){
		listen_t* lt = list_entry(p, listen_t, list);
		LOG_DBG("%s:%d fd:%d monitor by worker:%llu", lt->ip, lt->port, lt->fd, (long long unsigned)lt->accept_worker);
	}

	for(int i = 0; i < server->num_worker; ++i){
		worker_thread_t* worker = server->array_worker + i;
		LOG_INFO("worker:%llu connections:%llu, num alloc co:%d, num alloc ev:%d, free_co:%llu, free_ev:%llu, num request:%llu, cpu_usage:%d", (long long unsigned)worker, worker->conns, worker->num_alloc_co, worker->num_alloc_ev_ptr, worker->num_free_co, worker->num_free_ev_ptr, worker->num_request, worker->cpu_usage);
	}

#if 0
	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	long int total_time = (usage.ru_utime.tv_sec*1000+usage.ru_utime.tv_usec/1000+usage.ru_stime.tv_sec*1000+usage.ru_stime.tv_usec/1000) - (server->pre_usage.ru_utime.tv_sec*1000+server->pre_usage.ru_utime.tv_usec/1000+server->pre_usage.ru_stime.tv_sec*1000+server->pre_usage.ru_stime.tv_usec/1000);
	float cpu_usage = (1.0*total_time)/100;
	memcpy(&(server->pre_usage), &usage, sizeof(usage));
#endif

	float cpu_usage = get_cpu_usage(&(server->pre_usage), RUSAGE_SELF);
	LOG_DBG("cpu usage:%f", cpu_usage);
	MONITOR_FINAL("cpu_usage", (int)cpu_usage);

	FILE* fp = fopen("/proc/self/status", "r");
	if(!fp){
		LOG_ERR("failed to open status file");
		return;
	}

	char sz_line[1024];
	size_t n = 1024;
	int rss = 0;
	char* line = sz_line;
	while(getline(&line, &n, fp) != -1){ 
		if(strncmp(sz_line, "VmRSS:", 6) == 0){
			sscanf(sz_line, "VmRSS:\t%d\tkB", &rss);
			break;
		}

		n = 1024;
	}

	fclose(fp);
	MONITOR_FINAL("mem_usage", rss);
}

static void run_child(server_t* server)
{
	g_start_time[sizeof(g_start_time)-1] = 0;
	strtime_ymdhms_r(time(NULL), g_start_time, sizeof(g_start_time)-1);
	int rc = init_server(server);
	if(rc){
		LOG_ERR("failed to init server");
		return;
	}

	if(server->mt_fns.do_special_init && (server->mt_fns.do_special_init)(server)){
		LOG_ERR("failed to execute special init\n");
		return;
	}

	if(server->mt_fns.do_before_run){
		LOG_DBG("do before run");
		(server->mt_fns.do_before_run)(server);
	}

	list_head* rt = NULL;
	list_for_each(rt, &server->routines){
		pthread_routine_t* routine = list_entry(rt, pthread_routine_t, list);
		pthread_create(&(routine->ptid), NULL, routine->routine, routine->arg);
	}

	for(int i = 0; i < server->num_worker; ++i){
		worker_thread_t* worker = server->array_worker + i;
		if(worker->wt_fns.do_alloc_data){
			worker->custom_data = (worker->wt_fns.do_alloc_data)(worker);
		}

		run_http_client(worker->hc);
		pthread_create(&(worker->ptid), NULL, run_worker, worker);
	}

	run_kafka_consumers(server);
	run_kafka_producers(server);

	pthread_t zk_thread = 0;
	if(should_connect_2_zk(server)){
		pthread_create(&zk_thread, NULL, run_zk_thread, server);
	}

	add_signal_fd(server);
	getrusage(RUSAGE_SELF, &(server->pre_usage));
	int maxevs = 10;
	int n = 0;
	int i;
	struct epoll_event* evs = (epoll_event*)calloc(maxevs, sizeof(struct epoll_event));
	while(!server->exit){
		server->exit = g_svr_exit;
		log_server_stat(server);
		n = epoll_wait(server->epoll_fd, evs, maxevs, 10000);
		if(n == 0){
			continue;
		}

		for(i = 0; i < n; ++i){
			struct epoll_event* ev = evs + i;
			ev_ptr_t* ptr = (ev_ptr_t*)(ev->data.ptr);
			if((ev->events & EPOLLERR) || (ev->events & EPOLLHUP)){
				LOG_ERR("main thread epoll error on:%d", ptr->fd);
				ev->events |= (EPOLLIN|EPOLLOUT);
			}

			if((ev->events & EPOLLIN) && ptr->do_read_ev){
				(ptr->do_read_ev)(ptr);
			}else if((ev->events & EPOLLOUT) && ptr->do_write_ev){
				(ptr->do_write_ev)(ptr);
			}
		}
	}

	g_svr_exit = 1;
	g_stop_zk_thread = 1;
	if(zk_thread){
		pthread_join(zk_thread, NULL);
		sleep(10);
	}

	LOG_INFO("server stop");

	stop_server(server);
	if(server->mt_fns.do_after_stop){
		(server->mt_fns.do_after_stop)(server);
	}

	if(g_exit_status){
		exit(g_exit_status);
	}
}

static int run_as_daemon(server_t* server)
{
	switch(fork())
	{
		case -1:
			return -1;
		case 0:
			break;
		default:
			_exit(EXIT_SUCCESS);
	}

	if(setsid() == -1)
	{
		printf("failed to set session id. %s\n", strerror(errno));
		return -2;
	}

	int fd = open("/dev/null", O_RDWR, 0);
	if(fd !=-1)
	{
		if((dup2(fd, STDIN_FILENO)) == -1)
		{
			printf("failed to dup stdin to /dev/null. %s\n", strerror(errno));
			return -4;
		}

		if((dup2(fd, STDOUT_FILENO)) == -1)
		{
			printf("failed to dup stdout to /dev/null. %s\n", strerror(errno));
			return -5;
		}

		if((dup2(fd, STDERR_FILENO)) == -1)
		{
			printf("failed to dup stderr to /dev/null. %s\n", strerror(errno));
			return -6;
		}

		if(close(fd) == -1)
		{
			printf("failed to close fd /dev/null. %s\n", strerror(errno));
			return -7;
		}
	}

	pid_t child = fork();
	if(child == 0){
		run_child(server);
		return 0;
	}

	write_pid_file(child);
	while(1){
		int status;
		child = wait(&status);
		if(child < 0){
			LOG_ERR("failed to wait child.:%s", strerror(errno));
			break;
		}

		if(WIFEXITED(status)){
			LOG_ERR("child exit by calling exit or _exit:%d", WEXITSTATUS(status));
			if(WEXITSTATUS(status) == K_EXIT_BY_CONF_CHG || WEXITSTATUS(status) == 255 || WEXITSTATUS(status) == -1 ){
				goto restart_child;
			}
			break;
		}

		if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTERM){
			LOG_INFO("killed by term signal");
			break;
		}

restart_child:
		sleep(3);
		//unlink(get_pid_file(m_ctx.sz_application_name));
		child = fork();
		if(child == 0){
			if(server->config)
				json_object_put(server->config);
			server->config = load_cfg(g_sz_cfg);

			g_exit_status = 0;
			run_child(server);
		}else{
			write_pid_file(child);
		}
	}

	unlink(get_pid_file());
	return 0;
}

static void stop_server(server_t* server)
{
	for(int k = 0; k < server->num_worker; ++k){
		worker_thread_t* worker = server->array_worker + k;
		worker->exit = 1;
	}

	for(int k = 0; k < server->num_worker; ++k){
		worker_thread_t* worker = server->array_worker + k;
		pthread_join(worker->ptid, NULL);
	}

	/***************************************/
	/**
	 * It's the routine_self repsonsible for routine exiting and resource releasing
	 */
#if 0
	list_head* rt = NULL;
	list_for_each(rt, &server->routines){
		pthread_routine_t* routine = list_entry(rt, pthread_routine_t, list);
		pthread_cancel(routine->ptid);
	}

	rt = NULL;
	list_for_each(rt, &server->routines){
		pthread_routine_t* routine = list_entry(rt, pthread_routine_t, list);
		pthread_join(routine->ptid, NULL);
	}
#endif
	/***************************************/

	util_stop_logger();
}


static int fn_test_echo(ev_ptr_t* ptr, coroutine_t* co)
{
	return 0;
}

fn_method get_fn_method(worker_thread_t* worker, const char* name, int method)
{
	size_t len = 0;
	const char* p = name;
	while(p && *p && *p!=':'){
		++p;
		++len;
	}

	if(!len) {
		LOG_ERR("miss service name");
		return NULL;
	}

	server_t* server = (server_t*)(worker->mt);
	list_head* ls = NULL;
	list_for_each(ls, &(server->services)){
		service_t* svc = list_entry(ls, service_t, list);
		if(strncmp(svc->name, name, len) != 0 || strlen(svc->name) != len){
			continue;
		}

		if(method < 0 || method > svc->num_methods){
			LOG_ERR("invalid method tag:%d", method);
			return NULL;
		}

		return svc->methods[method];
	}

	LOG_ERR("invalid service name:%s", name);
	return fn_test_echo;
}

static int fn_on_recv_msg_from_pipe(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	struct cmd_t cmd;
	int len = 0;
	while((len = read(ptr->fd, &cmd, sizeof(cmd))) == sizeof(cmd)){
		switch(cmd.cmd){
			case K_CMD_YIELD_ACCEPT:
				{
					listen_t* lt = (listen_t*)cmd.arg;
					LOG_DBG("recv accept yiled cmd. worker:%llu, %s:%d fd:%d", (unsigned long long)worker, lt->ip, lt->port, lt->fd);
					list_add(&(lt->worker), &(worker->listens));
					add_one_listen(worker, lt);
				}
				break;
			case K_CMD_NOTIFY_DEP_SERVICE:
				{
					String_vector* strings = (String_vector*)cmd.arg;
					update_client_inst(worker, strings);
				}
				break;
			case K_CMD_NOTIFY_ASYNC_CONN_FIN:
				{
					async_conn_task_t* fin_conn = (async_conn_task_t*)cmd.arg;
					async_fin_conn_server(worker, fin_conn);
				}
				break;
			case K_CMD_NOTIFY_ASYNC_DB_ROUTINE_FIN:
				{
					mysql_query_t* query = (mysql_query_t*)cmd.arg;
					async_fin_mysql_execute(query);
				}
				break;
			case K_CMD_NOTIFY_ASYNC_REDIS_FIN:
				{
					rpc_ctx_t* ctx = (rpc_ctx_t*)cmd.arg;
					async_fin_redis_execute(ctx);
				}
				break;
			case K_CMD_NOTIFY_ASYNC_HTTP_FIN:
				{
					rpc_ctx_t* ctx = (rpc_ctx_t*)cmd.arg;
					async_fin_http_request(ctx);
				}
				break;
			default:
				if(worker->wt_fns.do_recv_notify){
					(worker->wt_fns.do_recv_notify)(worker, cmd);
					//execute_pipe_notify_in_co(ptr, &cmd);
				}else{
					LOG_INFO("worker:%llu recv unknown cmd:%d", (long long unsigned)worker, cmd.cmd);
				}
				break;
		}
	}

	return 0;
}

static int init_wt(worker_thread_t* wt, json_object* config)
{
	wt->pb_co_id = 0xffffffff;
	wt->swoole_co_id = 10;
	wt->last_check_timeout_time = get_milli_second();
	wt->next_check_index = 0;

	wt->ev_ptr_cache = util_create_cache();
	wt->co_cache = util_create_cache();

	wt->wt_co = co_create(NULL, NULL, NULL,  NULL, NULL);
	assert(wt->wt_co != NULL);

	init_timers(&(wt->timers), do_check_co_timeout, do_check_heartbeat_timeout, do_check_idle_timeout, do_check_disconnect_timeout);
	wt->req_co_timeout_wheel = (list_head*)calloc(K_MAX_TIMEOUT, sizeof(list_head));
	wt->heartbeat_wheel = (list_head*)calloc(K_MAX_TIMEOUT, sizeof(list_head));
	wt->idle_time_wheel = (list_head*)calloc(K_MAX_TIMEOUT, sizeof(list_head));
	wt->disconnected_client_wheel = (list_head*)calloc(K_MAX_TIMEOUT, sizeof(list_head));

	wt->num_free_ev_ptr = 0;
	INIT_LIST_HEAD(&(wt->free_ev_ptr_list));

	for(size_t i = 0; i < K_MAX_TIMEOUT; ++i){
		INIT_LIST_HEAD(wt->req_co_timeout_wheel+i);
		INIT_LIST_HEAD(wt->heartbeat_wheel+i);
		INIT_LIST_HEAD(wt->idle_time_wheel+i);
		INIT_LIST_HEAD(wt->disconnected_client_wheel+i);
	}

	wt->epoll_fd = epoll_create(10240);
	pipe(wt->pipefd);

	//accept fd
    int flag = fcntl(wt->pipefd[0], F_GETFL);
    fcntl(wt->pipefd[0], F_SETFL, flag|O_NONBLOCK);
	util_un_fcntl(wt->pipefd[1]);

	ev_ptr_t* ptr = get_ev_ptr(wt, wt->pipefd[0]);
	ptr->do_read_ev = fn_on_recv_msg_from_pipe;
	ptr->fd = wt->pipefd[0];
	ptr->arg = wt;
	ptr->ev = 0;
	printf("add pipe:%d worker:%lld\n", ptr->fd, (long long int)wt);
	add_read_ev(wt->epoll_fd, ptr);

	//kafka fd
	if(!list_empty(&(((server_t*)wt->mt))->kafka_consumers)){
		pipe(wt->kafka_pipefd);
		flag = fcntl(wt->kafka_pipefd[0], F_GETFL);
		fcntl(wt->kafka_pipefd[0], F_SETFL, flag|O_NONBLOCK);
		util_un_fcntl(wt->kafka_pipefd[1]);

		ev_ptr_t* kafka_ptr = get_ev_ptr(wt, wt->kafka_pipefd[0]);
		kafka_ptr->do_read_ev = fn_on_recv_kafka_msg;
		kafka_ptr->fd = wt->kafka_pipefd[0];
		kafka_ptr->arg = wt;
		kafka_ptr->ev = 0;
		printf("add pipe:%d worker:%lld\n", kafka_ptr->fd, (long long int)wt);
		add_read_ev(wt->epoll_fd, kafka_ptr);
	}

	wt->num_free_co = 0;
	INIT_LIST_HEAD(&(wt->free_co_list));
	INIT_LIST_HEAD(&(wt->listens));
	INIT_LIST_HEAD(&(wt->dep_service));
	add_dep_service(wt, config);

	int rc = connect_2_redis(&(wt->redis), config);
	if(rc){
		LOG_ERR("failed to connect 2 redis");
	}

	json_object* js_mysql;
	if(json_object_object_get_ex(config, "mysql", &js_mysql)){
		rc = connect_2_mysql(wt, js_mysql);
		if(rc){
			LOG_ERR("failed to connect 2 mysql");
		}
	}

	wt->hc = malloc_http_client();
	return 0;
}

static void init_logger(json_object* conf)
{
	int rc = util_init_bim_logger(g_app_name, conf);
	if(rc){
		printf("failed to init logger\n");
		return;
	}

	util_logger_set_monitor_upload_cb(fn_update_monitor_info);
}

static void init_limitation()
{
    struct rlimit orig_limit;
    struct rlimit new_limit;

    if(getrlimit(RLIMIT_CORE, &orig_limit) == 0){
        new_limit.rlim_cur = new_limit.rlim_max = RLIM_INFINITY;
        if(setrlimit(RLIMIT_CORE, &new_limit) != 0){
            new_limit.rlim_cur = new_limit.rlim_max = orig_limit.rlim_max;
            setrlimit(RLIMIT_CORE, &new_limit);
        }
    }
    
    if(getrlimit(RLIMIT_NOFILE, &orig_limit) == 0){
        if(orig_limit.rlim_cur < 1000000){
            new_limit.rlim_cur = 1000000;
            new_limit.rlim_max = new_limit.rlim_cur > orig_limit.rlim_max?new_limit.rlim_cur:orig_limit.rlim_max;
            if(setrlimit(RLIMIT_NOFILE, &new_limit) != 0){
				perror("failed to set no file limit\n");
                new_limit.rlim_cur = new_limit.rlim_max = orig_limit.rlim_max;
                setrlimit(RLIMIT_NOFILE, &new_limit);
            }
        }
    }
}

static int do_recv_signal(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	server_t* server = (server_t*)(ptr->arg);
	struct signalfd_siginfo sfd_info;
	ssize_t size = read(server->sgfd, &sfd_info, sizeof(struct signalfd_siginfo));
	if(size != sizeof(struct signalfd_siginfo)){
		LOG_ERR("failed to get info from signalfd");
		return 0;
	}

	int signo = sfd_info.ssi_signo;
	LOG_INFO("recv signal:%d", signo);
	switch(signo){
		case SIGTERM:
			(server->mt_fns.do_recv_term_signal)(server);
			break;
		case SIGQUIT:
			(server->mt_fns.do_recv_quit_signal)(server);
			break;
		case SIGUSR1:
			(server->mt_fns.do_recv_reload_signal)(server);
			break;
		default:
			LOG_ERR("uncaught signal");
			break;
	}

	return 0;
}

static void do_recv_quit_signal(server_t* server)
{
	server->exit = 1;
	LOG_INFO("recv quit signal");
}

static void do_recv_term_signal(server_t* server)
{
	server->exit = 1;
	LOG_INFO("recv term signal");
}

static void do_recv_reload_signal(server_t* server)
{
	LOG_INFO("recv reload signal");
}

static void* run_worker(void* arg)
{
	set_sched_cpu_affinity();

	worker_thread_t* worker = (worker_thread_t*)arg;
	monitor_accept(worker);
	worker->cpu_usage = 0;
	getrusage(RUSAGE_THREAD, &worker->last_st);

	run_timers(&worker->timers);
	worker->last_check_timeout_time = get_milli_second();
	worker->next_check_index = 0;

	uint64_t last_tick = get_monotonic_milli_second();
	int maxevs = 1024;
	int fds[1024];
	int n = 0;
	int i;
	struct epoll_event* evs = (epoll_event*)calloc(maxevs, sizeof(struct epoll_event));
	int wait_time = get_next_timeout(&(worker->timers));
	while(!worker->exit){
		n = epoll_wait(worker->epoll_fd, evs, maxevs, wait_time);
        struct epoll_event* ev = NULL;
		for(i = 0; i < n; ++i){
		    ev = evs + i;
			ev_ptr_t* ptr = (ev_ptr_t*)(ev->data.ptr);
			fds[i] = ptr->fd;
		}

		for(i = 0; i < n; ++i){
		    ev_ptr_t* ptr = (ev_ptr_t*)util_get_item(worker->ev_ptr_cache, &fds[i], sizeof(fds[i]));
		    if (NULL == ptr){
		        LOG_ERR("util_get_item get null ev_ptr:fd:%d", fds[i]);
		        MONITOR_ACC("reuse_recycle's_ev_ptr", 1);
                continue;
		    }
			ev = evs + i;
			if(ev->events & (EPOLLERR|EPOLLHUP)){
				ev->events |= (EPOLLIN|EPOLLOUT);
			}

			if((ev->events & EPOLLIN) && ptr->do_read_ev){
				(ptr->do_read_ev)(ptr);
			}else if((ev->events & EPOLLOUT) && ptr->do_write_ev){
				LOG_DBG("write event occured:%d, worker:%llu , %s:%d fd:%d\n", ptr->fd, (long long unsigned)arg, ptr->ip, ptr->port, ptr->fd);
				(ptr->do_write_ev)(ptr);
			}

		}

		do_check_timer_v2(worker);

		wait_time = get_next_timeout(&(worker->timers));
		LOG_DBG("next wait time:%d", wait_time);
		uint64_t now = get_monotonic_milli_second();
		if(now > last_tick+10000){
			last_tick = now;
			worker->cpu_usage = get_cpu_usage(&(worker->last_st), RUSAGE_THREAD) + 1;
			LOG_DBG("worker:%llu cpu usage:%llu", (long long unsigned)worker, worker->cpu_usage);
		}
	}
	return NULL;
}

int notify_worker(worker_thread_t* worker, cmd_t cmd)
{
	int rc = write(worker->pipefd[1], &cmd, sizeof(cmd));
	if(rc != sizeof(cmd)){
		LOG_ERR("failed to notify worker");
		return -1;
	}
	return 0;
}

static const char* get_pid_file()
{
	static char sz_pid_file [1024]={0}; 
	snprintf(sz_pid_file, sizeof(sz_pid_file)-1, "/var/run/%s.pid", g_app_name); 
	return sz_pid_file;
}

static void write_pid_file(int pid)
{
	const char* sz_pid_file = get_pid_file(); 
	if(g_pid_file){
		close(g_pid_file);
		g_pid_file = 0;
	}

	g_pid_file = open(sz_pid_file, O_RDWR|O_CREAT|O_EXCL, 0666);
	if(g_pid_file < 0){
		LOG_ERR("failed to open pid file");
		return;
	}

	char sz_pid[20];
	snprintf(sz_pid, sizeof(sz_pid), "%d", pid);
	write(g_pid_file, sz_pid, strlen(sz_pid));
	return;
}

void set_code_2_msg(server_t* server, fn_err_code_2_str fn)
{
	server->fn_code_2_str = fn;
}

