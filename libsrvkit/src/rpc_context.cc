
#include <server_inner.h>

void* get_worker_custom_data(rpc_ctx_t* ctx)
{
	if(NULL == ctx || NULL == ctx->co || NULL == ctx->co->worker){
		return NULL;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	return  worker->custom_data;
}

void set_hash_key(rpc_ctx_t* ctx, uint64_t key)
{
	if(NULL == ctx || NULL == ctx->co){
		LOG_ERR("miss co");
		return ;
	}

	ctx->co->hash_key = key;
}

const userctx_t*  get_user_ctx_from_rpc_ctx(rpc_ctx_t* ctx)
{
	if(NULL == ctx || NULL == ctx->co){
		return NULL;
	}

	return &(ctx->co->uctx);
}

void regist_rpc_info(rpc_info_t* rpc, const char* service, const char* method)
{
	if(!rpc){
		return;
	}

	strncpy(rpc->service, service, sizeof(rpc->service));
	strncpy(rpc->method, method, sizeof(rpc->method));
}
