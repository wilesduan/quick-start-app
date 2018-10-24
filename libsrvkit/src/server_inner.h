#ifndef _LIB_SRV_KIT_SERVER_INNER_H_
#define _LIB_SRV_KIT_SERVER_INNER_H_

#include <json.h>
#include <pthread.h>
#include <co_routine.h>
#include <bim_util.h>
#include <zookeeper.h>
#include <hircluster.h>
#include <mysql_wrapper.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>
#include <async_task.h>
#include <timer_def.h>
#include <connector.h>
#include <blink.pb.h>
#include <net.h>


#define K_MAX_NAME_LEN 20
#define K_LISTEN_ADDR_LEN 128
#define K_DEFALUT_IDLE_TIME 60
#define K_PB_MAGIC 0xFFFF 

#define K_EXIT_BY_CONF_CHG 127

#define K_CMD_YIELD_ACCEPT 1
#define K_CMD_NOTIFY_DEP_SERVICE 2
#define K_CMD_NOTIFY_ASYNC_CONN_FIN 3
#define K_CMD_NOTIFY_ASYNC_DB_ROUTINE_FIN 4
#define K_CMD_NOTIFY_ASYNC_REDIS_FIN 5


//#pragma pack(8)
//main thread
struct server_t;
struct worker_thread_t;
struct ev_ptr_t;
typedef int (*fn_special_init)(server_t* server);
typedef void(*fn_before_run)(server_t* server);
typedef void(*fn_after_stop)(server_t* server);
typedef void(*fn_recv_quit_signal)(server_t* arg);
typedef void(*fn_recv_term_signal)(server_t* arg);
typedef void(*fn_recv_reload_signal)(server_t* arg);
typedef void(*fn_on_recv_upd_data)(worker_thread_t* worker, int udp_sock_fd, void* body, sockaddr_in* addr, socklen_t addr_len);
typedef const char*(*fn_err_code_2_str)(int err_code);
typedef int(*fn_method)(ev_ptr_t* ptr, coroutine_t* co);

typedef struct mt_call_backs_t
{
	fn_special_init do_special_init;
	fn_before_run do_before_run;
	fn_after_stop do_after_stop;
	fn_recv_quit_signal do_recv_quit_signal;
	fn_recv_term_signal do_recv_term_signal;
	fn_recv_reload_signal do_recv_reload_signal;
	fn_on_recv_upd_data do_process_udp_data;
	fn_method do_process_http_data;
	mt_call_backs_t(){
		do_special_init = 0;
		do_before_run = 0;
		do_after_stop = 0;
		do_recv_quit_signal = 0;
		do_recv_term_signal = 0;
		do_recv_reload_signal = 0;
		do_process_udp_data = 0;
		do_process_http_data = 0;
	}
}mt_call_backs_t;

typedef int(*fn_on_epoll_ev)(void* arg);
struct proto_client_inst_t;
typedef int(*fn_process_request)(ev_ptr_t*);
typedef struct ev_ptr_t
{
	fn_on_epoll_ev do_read_ev;
	fn_on_epoll_ev do_write_ev;
	fn_on_epoll_ev do_excpt_ev;
	uint32_t ev;
	int fd;
	int epoll_del;
	bool udp_sock;

	char ip[16];
	int port;
	void* arg;

	void* listen;

	struct util_buff_chain_t* recv_chain;
	struct util_buff_chain_t* send_chain;

	struct proto_client_inst_t* cli;

	int heartbeat_milli_offset;
	list_head heartbeat_wheel;

	int idle_milli_offset;
	list_head idle_time_wheel;
	size_t idle_time;

	fn_process_request process_handler;
	bool no_cb;
	list_head co_list;
	list_head free_ev_ptr_list;
	int num_package_in_5s;
	time_t package_time;

	list_head async_req_out_list;
	int num_async_out;
	int tmp;

	circuit_breaker_t* breaker;
}ev_ptr_t;

struct worker_thread_t;
struct cmd_t;

typedef struct redis_cmds_t
{
	int executed;
	list_head cmds;
}redis_cmds_t;

struct redis_client_t;
typedef struct rpc_ctx_t
{
	ev_ptr_t* ptr;
	coroutine_t* co;
	void* arg;
	mysql_inst_t* mysql_inst;
	redis_cmds_t redis_cmds;
	redis_client_t* redis;
	rpc_ctx_t(){
		ptr = NULL;
		co = NULL;
		arg = NULL;
		mysql_inst = NULL;
		redis = NULL;
		redis_cmds.executed = 0;
		INIT_LIST_HEAD(&redis_cmds.cmds);
	}
}rpc_ctx_t;
//worker thread
typedef int(*fn_cb_conn_ev)(worker_thread_t* worker, int fd);
typedef int(*fn_cb_accept_ev)(ev_ptr_t* ptr);
typedef void* (*fn_cb_custom_data)(worker_thread_t* worker);
typedef void(*fn_recv_pipe_notify)(worker_thread_t*, cmd_t);

typedef struct wt_call_backs_t
{
	fn_cb_conn_ev do_shutdown_conn;
	fn_cb_accept_ev do_accept_conn;
	fn_cb_custom_data do_alloc_data;
	fn_recv_pipe_notify do_recv_notify;
	wt_call_backs_t(){
		do_shutdown_conn = 0;
		do_accept_conn = 0;
		do_alloc_data = 0;
		do_recv_notify = 0;
	}
}wt_call_backs_t;

typedef struct cmd_t
{
	int cmd;
	void* arg;
}cmd_t;

enum en_protocal_type
{
	EN_PROTOCAL_PB = 1,
	EN_PROTOCAL_SWOOLE = 2,
	EN_PROTOCAL_HTTP2 = 3,
};

enum en_sock_type
{
	EN_SOCK_TCP = 0,
	EN_SOCK_UDP = 1,
};

typedef struct http2_ssl_connection_t
{
	int fd;
	SSL_CTX* ssl_ctx;
	SSL* ssl;
	nghttp2_session* session;
	int want_io;
}http2_ssl_connection_t;

typedef struct breaker_setting_t
{
	int open;
	int failure_threshold_in_10s;
	int half_open_ratio;
}breaker_setting_t;

typedef struct proto_client_inst_t
{
	char ip[30];
	int port;
	char* service;
	int timeout;

	char invalid;
	size_t num_request;
	size_t num_failed;
	size_t num_timeout;

	size_t num_fail_in_60s;

	ev_ptr_t* ptr;
	size_t num_conn_failed;

	int disconnect_milli_offset;
	list_head disconnected_client_wheel;

	en_protocal_type proto_type;
	en_sock_type sock_type;

	time_t conn_time;
	int req_queue_size;
	breaker_setting_t* breaker_setting;

	http2_ssl_connection_t ssl_conn;
	char* ssl_cert_path;
	char* ssl_cert_key;

	int weight;//cpu usage
	list_head weight_list;
}proto_client_inst_t;

enum en_load_balance
{
	EN_LOAD_BALANCE_ROUND_ROBIN = 1,
	EN_LOAD_BALANCE_WEIGHT = 2,
};

#define K_CLI_WEIGHT_SIZE 64 
typedef struct proto_client_t
{
	list_head list;

	char* service;
	char* url;
	char from_zk;
	char hash;
	int timeout;
	int load_balance;

	breaker_setting_t breaker_setting;

	en_protocal_type proto_type;
	en_sock_type sock_type;

	char* watcherCtx[2];

	int req_queue_size;
	size_t next_cli;
	size_t num_clients;
	proto_client_inst_t* cli_inst_s;
	char* ssl_cert_path;
	char* ssl_cert_key;

	size_t weight_idx;
	list_head weight_array[K_CLI_WEIGHT_SIZE];
	uint64_t weight_bitmap;
}proto_client_t;

enum redis_server_type
{
	EN_REDIS_NONE = 0,
	EN_REDIS_CLUSTER = 1,
	EN_REDIS_TW = 2,
};

typedef struct redis_ctx_t
{
	char* fmt_cmd;
	size_t len;

	redisReply* reply;

	list_head list;
	char* err_str;
	int err;
}redis_ctx_t;

typedef struct redis_client_t
{
	redis_server_type type;
	char* host;
	int port;
	void* client;
	list_head replys;
	time_t last_ping;
	int pipeline;
	char* passwd;
	int num_commands;
	struct timeval tv;
	int has_cmd;
	async_routine_t* asyncer;

	redis_client_t* redis_4_test;
}redis_client_t;

typedef struct worker_thread_t
{
	int idx;
	coroutine_t* wt_co;
	int epoll_fd;
	int pipefd[2];
	int kafka_pipefd[2];
	pthread_t ptid;
	wt_call_backs_t wt_fns;
	volatile int exit;
	void* next;
	void* mt;
	cache_t* ev_ptr_cache;
	//mem_pool_t* ev_ptr_pool;
	//util_pool_t* buff_chain_pool;

	size_t conns;

	cache_t* co_cache;

	size_t num_free_co;
	list_head free_co_list;

	size_t num_free_ev_ptr;
	list_head free_ev_ptr_list;

	list_head listens;
	list_head dep_service;

	time_wheel_t timers;

	uint64_t last_check_timeout_time;//milliseconds
	size_t next_check_index;
	list_head* req_co_timeout_wheel;
	list_head* heartbeat_wheel;
	list_head* idle_time_wheel;
	list_head* disconnected_client_wheel;

	redis_client_t redis;
	mysql_wrapper_t mysql_wrapper;
	void* custom_data;

	void* apns_conn;

	uint32_t swoole_co_id;
	uint64_t pb_co_id;
	int num_alloc_co;
	int num_alloc_ev_ptr;

	void* pb_mc_collector;
	struct rpc_ctx_t pipe_ctx;

	uint64_t num_request;
	struct rusage last_st;
	int cpu_usage;
}worker_thread_t;

typedef void* (*fn_pthread_routine)(void*);

typedef struct pthread_routine_t
{
	list_head list;
	pthread_t ptid;
	fn_pthread_routine routine;
	void* arg;
}pthread_routine_t;

typedef struct swoole_method_t
{
	char* method_name;
	fn_method method;
}swoole_method_t;

typedef struct service_t
{
	list_head list;

	const char* name;
	int num_methods;
	fn_method* methods;
	swoole_method_t* swoole_meth;
}service_t;

enum en_listen_type
{
	EN_LISTEN_TCP = 1,
	EN_LISTEN_UDP = 2,
	EN_LISTEN_HTTP = 3,
};

typedef struct listen_t
{
	list_head list;
	list_head worker;
	en_listen_type type;
	char ip[30];
	int port;
	int fd;
	fn_on_epoll_ev do_epoll_ev;
	ev_ptr_t* ptr;

	int accept_num_before_yield;
	int idle_time;

	int count;
	char** lt_services;
	char heartbeat;
	char tag;//public internet
	int limit;
	worker_thread_t* accept_worker;
	int accept_strategy;
}listen_t;

typedef struct server_t
{
	char* appname;
	json_object* config;

	fn_err_code_2_str fn_code_2_str;

	size_t max_conns_per_worker;
	int num_worker;
	worker_thread_t* array_worker;
	mt_call_backs_t mt_fns;
	wt_call_backs_t wt_fns;

	int epoll_fd;
	int sgfd;

	int exit;

	zhandle_t* zkhandle;

	list_head routines;
	list_head services;
	list_head listens;

	struct rusage pre_usage;

	list_head kafka_consumers;
	list_head kafka_producers;

	async_connector_t* async_connectors;
	int num_connectors;
}server_t;

int notify_worker(worker_thread_t* worker, cmd_t cmd);
int connect_2_real_redis(redis_client_t* redis, const char* link, const char* link_4_test = NULL);
fn_method get_fn_method(worker_thread_t* worker, const char* name, int method);

//conf.cc
json_object* load_cfg(const char* cfg);

//connector
void async_conn_server(worker_thread_t* worker, proto_client_inst_t* cli);
void async_fin_conn_server(worker_thread_t* worker, async_conn_task_t* fin_conn);
void run_async_connector(server_t* server);

//co_routine.cc
coroutine_t* get_co_by_req_id(ev_ptr_t* ptr, uint64_t req_id);
void do_fin_request(coroutine_t* co);
void save_batch_co(coroutine_t* co, ev_ptr_t* ptr, const char* service, int method, uint64_t ss_req_id);
void chg_co_timeout(coroutine_t* co, ev_ptr_t* cli);
int prepare_co_before_async_call(coroutine_t* co, ev_ptr_t* cli);
void add_co_to_async_list(worker_thread_t* worker, coroutine_t* co, ev_ptr_t* cli);
coroutine_t* get_co_ctx(worker_thread_t* worker, fn_method fn);

//misc.cc
char* read_file_content(const char* cfg);
void parse_zk_url(const char* url, char** host, char** path, char** added_group);
void async_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr);
void ack_req_with_buff(ev_ptr_t* ptr, coroutine_t* co, int ret_code, const char* buf, size_t size, const char* err_msg = NULL);
void ack_req_with_rsp(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg = NULL);
void init_proto_uctx(blink::UserContext* proto_user_ctx);

//event.cc
void add_co_timeout_wheel(worker_thread_t* worker, coroutine_t* co);
void add_client_inst_2_wheel(worker_thread_t* worker, proto_client_inst_t* cli);
void add_ev_ptr_2_heartbeat_wheel(worker_thread_t* worker, ev_ptr_t* ptr);
void add_ev_ptr_2_idle_time_wheel(worker_thread_t* worker, ev_ptr_t* ptr);
void recycle_ev_ptr(ev_ptr_t* ptr);
void shut_down_ev_ptr(ev_ptr_t* ptr);
void add_read_ev(int epoll_fd, ev_ptr_t* ptr);
void add_write_ev(int epoll_fd, ev_ptr_t* ptr);
void clear_ev_ptr(ev_ptr_t* ptr);
void cancel_write_ev(int epoll_fd, ev_ptr_t* ptr);
void do_check_co_timeout(worker_thread_t* worker, list_head* node);
void do_check_heartbeat_timeout(worker_thread_t* worker, list_head* p);
void do_check_idle_timeout(worker_thread_t* worker, list_head* p);
void do_check_disconnect_timeout(worker_thread_t* worker, list_head* p);
ev_ptr_t* get_ev_ptr(worker_thread_t* worker,int fd);

//mysql
int connect_2_mysql(worker_thread_t* wt, json_object* config);

//net.cc
void add_one_listen(worker_thread_t* worker, listen_t* lten);
void init_client_inst(worker_thread_t* worker, proto_client_inst_t* cli, const std::pair<char*, int>& ip_port, int async_fd);
void add_dep_service(worker_thread_t* wt, json_object* config);
void monitor_accept(worker_thread_t* worker);
void update_client_inst(worker_thread_t* worker, String_vector* strings);
int do_listen(server_t* server);
int do_write_msg_to_tcp(void* arg);
proto_client_t* get_clients_by_service(worker_thread_t* worker, const char* service);
ev_ptr_t* get_cli_ptr_by_ip(worker_thread_t* worker, const char* service, const char* ip, int port);
ev_ptr_t* get_cli_ptr(worker_thread_t* worker, coroutine_t* co, const char* service);

//http2
int http2_ping_mark(ev_ptr_t* ptr);

//mc.cc
void mc_collect(worker_thread_t* worker, rpc_info_t* rpc_info, int cost, int code, int acc = 0, const char* ss_trace_id_s = NULL);

//pb.cc
int process_pb_request(ev_ptr_t* ptr, const blink::MsgBody& body);
int process_pb_request_from_ev_ptr(ev_ptr_t* ptr);
void async_pb_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr);
int serialize_pb_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg = " ");
int serialize_buff_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, const char* buf, size_t size, const char* err_msg = " ");
int async_req_with_pb_msg(worker_thread_t* worker, coroutine_t* co, const char* service, int method, ::google::protobuf::Message* msg, int timeout=800);
int async_req_with_pb_buff(worker_thread_t* worker, coroutine_t* co, const char* service, int method, const char* msg, size_t size);
int async_req_pb_2_ip(worker_thread_t* worker, coroutine_t* co, const char* service, int method, const char* ip, int port, ::google::protobuf::Message* msg);
void init_msg_head(blink::MsgHead& head);


//swoole.cc
void pad_mem_with_iovecs(const std::vector<iovec>& iovs, char* mem, size_t need_len);
int process_swoole_request(ev_ptr_t* ptr, swoole_head_t* head, char* body);
int process_swoole_request_from_ev_ptr(ev_ptr_t* ptr);
void async_swoole_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr);
int serialize_json_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg);
int async_req_with_swoole_msg(worker_thread_t* worker, coroutine_t* co, const char* service, const char* method, ::google::protobuf::Message* msg, int v = 1, int timeout=800);
fn_method get_swoole_fn_method(worker_thread_t* worker, const char* service, const char* method_name);
int do_process_swoole_request(worker_thread_t* worker, ev_ptr_t* ptr, swoole_head_t* head, fn_method fn, json_object* root, json_object* header, json_object* swoole_body, json_object* swoole_http, json_object* swoole_ctx);
uint32_t gen_32_id(worker_thread_t* worker);

//zk.cc
bool should_connect_2_zk(server_t* server);
void* run_zk_thread(void* arg);
void sync_get_content_from_zk(const char* host, const char* path, char* buffer, int* len);
bool compare_ip_port(const std::pair<char*, int>& p1, const std::pair<char*, int>& p2);
void get_ip_port_from_zk(const char* url, std::vector<std::pair<char*, int> >& ip_ports);

//http.cc
int process_http_request_from_ev_ptr(ev_ptr_t* ptr);
int serialize_http_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg);
int ack_http_repsone(ev_ptr_t* ptr, int http_code, const char* code_desc, const char* content_type, const char* content);


//#pragma pack()
#endif
