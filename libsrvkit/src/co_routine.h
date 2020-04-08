#ifndef __LIB_SRV_KIT_CO_ROUTINE_H_
#define __LIB_SRV_KIT_CO_ROUTINE_H_

#include <stdint.h>
#include "coctx.h"
#include <list.h>
#include <google/protobuf/message.h>
#include <swoole_def.h>
#include <timer_def.h>

struct coroutine_t;
typedef int (*fn_co_routine)(void* arg1, void* arg2);
typedef void (*fn_co_recycle)(void* recycler, coroutine_t* co);

#define K_IP_LEN 16
#define K_PLATFORM_LEN 16
typedef struct userctx_t
{
	uint64_t uid;
	char cli_ip[K_IP_LEN];
	char conn_ip[K_IP_LEN];
	unsigned short conn_port;
	char platform[K_PLATFORM_LEN];
	int dev_type;
	uint64_t ss_trace_id;
	char ss_trace_id_s[32];
	int32_t dev_crc32;
	int flag_test;
}userctx_t;

typedef struct rpc_info_t
{
	char service[32];
	char method[32];
	char ip[24];
	uint64_t start_time;
}rpc_info_t;

typedef struct batch_rpc_result_t
{
	list_head batch_rslt;
	rpc_info_t rpc_info;
	//char service[32];
	//int method;
	int sys_code;
	uint64_t req_id;
	::google::protobuf::Message* rsp;
	void* ptr;
	char finish;
	uint64_t ts;//ms
}batch_rpc_result_t;

typedef struct coroutine_t
{
	coctx_t ctx;

	fn_co_routine pfn;
	void* arg1;
	void* arg2;

	fn_co_recycle pfn_recycle;
	void* recycler;

	char start;
	char end;

	coroutine_t* pre;

	const char* params;
	size_t size;

	uint64_t hash_key;
	uint32_t cmd_id;
	uint64_t cli_req_id;
	uint64_t session_code;
	//uint64_t uid;
	uint64_t ss_req_id;
	//int fd;
	uint32_t sys_code;
	char err_msg[256];
	uint64_t cache_req_id;

	rpc_info_t rpc_info;

	list_head free_list;

	timer_event_t rpc_timer;
	//int req_co_milli_offset;
	//list_head req_co_timeout_wheel;

	char swoole_head[sizeof(swoole_head_t)];
	//void* swoole_head;
	void* json_req_root;
	void* json_swoole_body_head;
	void* json_swoole_body_body;
	void* json_swoole_body_http;
	void* json_swoole_body_data;
	void* json_swoole_response;

	char wait_reply;
	userctx_t uctx;

	void* worker;
	list_head ptr_list;
	char ptr_closed;

	list_head async_req_out_list;
	void* async_cli_ptr;

	void* proto_user_ctx;

	int batch_mode;
	int batch_req_num;
	list_head batch_rslt_list;
	int timeout;
	int need_trace_point;
	uint64_t biz_config_version;
	coroutine_t()
	{
		pre = NULL;
		timeout = 800;
	}
}coroutine_t;

coroutine_t* co_create(fn_co_routine pfn, void* arg1, void* arg2, fn_co_recycle precycle, void* recycler);
void co_resume(coroutine_t* routine);
void co_yield(coroutine_t* curr);
void co_destroy(coroutine_t** routine);
void co_release(coroutine_t** routine);

void co_free_batch_rslt_list(coroutine_t* co);

inline bool is_co_in_batch_mode(coroutine_t* co){return co->batch_mode;};
void add_batch_rsp_rslt(coroutine_t* co);
batch_rpc_result_t* get_co_last_req_rslt(coroutine_t* co);
batch_rpc_result_t* get_co_req_rslt_by_req_id(coroutine_t* co, uint64_t ss_req_id);
#endif//__LIB_SRV_KIT_CO_ROUTINE_H_
