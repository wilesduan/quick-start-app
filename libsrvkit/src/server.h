#ifndef _LIB_SRV_KIT_SERVER_H_
#define _LIB_SRV_KIT_SERVER_H_
#include <server_inner.h>
#include <http2_client.h>
#include <redis.h>
#include <google/protobuf/message.h>
#include <blink.pb.h>
#include <kafka.h>
#include <async_task.h>
#include <http_client.h>
#include <vector>

server_t* malloc_server(int argc, char** argv);

void add_mt_call_backs(server_t* server, mt_call_backs_t mt_fns);
void add_wt_call_backs(server_t* server, wt_call_backs_t wt_fns);

void add_routine(server_t* server, fn_pthread_routine routine, void* arg);
void set_code_2_msg(server_t* server, fn_err_code_2_str fn);
int get_lang_by_rpc_ctx(rpc_ctx_t* ctx);

void add_service(server_t* server, service_t* service);
int run_server(server_t* server);

void* get_worker_custom_data(rpc_ctx_t* ctx);
void set_hash_key(rpc_ctx_t* ctx, uint64_t key);
MYSQL* get_mysql_from_rpc(rpc_ctx_t* rpc, uint64_t shard_key);
MYSQL* get_mysql_from_rpc_by_id(rpc_ctx_t* rpc, const char* id);

const userctx_t*  get_user_ctx_from_rpc_ctx(rpc_ctx_t* ctx);
void set_trace_point_cost(blink::TracePoint* point, const char* service, const char* method, int milli_cost);
void add_trace_point(rpc_ctx_t* ctx, const char* service, const char* method, const char* content, int milli_cost);
void refill_trace_point(rpc_ctx_t* ctx, const char* service, const char* method, int milli_cost, int code);
void log_trace_point(blink::UserContext* uctx);

void begin_batch_request(coroutine_t* co);
void end_batch_request(coroutine_t* co, std::vector<int>* rets=NULL);
int switch_dbname_charset(mysql_inst_t* inst, int flag = 0);

void regist_rpc_info(rpc_info_t* rpc, const char* service, const char* method);

int invoke_http_request(rpc_ctx_t* ctx, blink::req_http* req, blink::rsp_http* rsp);
#endif

