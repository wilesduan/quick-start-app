#ifndef __LIBSRVKIT_REDIS_H__
#define __LIBSRVKIT_REDIS_H__

#include <server_inner.h>
#include <hircluster.h>

redisReply* call_redis(rpc_ctx_t* ctx, const char* cmd, ...);
redisReply* call_redisv(rpc_ctx_t* ctx, const std::vector<std::string>& cmds);

int begin_redis_pipeline(rpc_ctx_t* ctx);
int call_add_pipeline_command(rpc_ctx_t* ctx, const char* cmd, ...);
int call_add_pipeline_commandv(rpc_ctx_t* ctx, const std::vector<std::string>& cmds);
redisReply* get_pipeline_reply(rpc_ctx_t* ctx);
void end_redis_pipeline(rpc_ctx_t* ctx);

void prepare_redis_status(redis_client_t* redis, bool ping = true);

void async_fin_redis_execute(rpc_ctx_t* ctx);

void copy_redis_client(redis_client_t* src, redis_client_t* dst);

int connect_2_redis(redis_client_t* redis, json_object* config);
#endif//__LIBSRVKIT_REDIS_H__
