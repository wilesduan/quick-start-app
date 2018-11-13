#include <co_routine.h>
#include <coctx.h>
#include <blink.pb.h>
#include <server_inner.h>
#define K_CO_CACHE_NUM 1000

extern int g_use_cluster_redis;
extern "C"
{
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};
static void co_swap(coroutine_t* curr, coroutine_t* next);

coroutine_t* co_create(fn_co_routine pfn, void* arg1, void* arg2, fn_co_recycle precyle, void* recycler)
{
	size_t size = g_use_cluster_redis?256*1024:128*1024;
	char* membuff = (char*)malloc(size);
	if(NULL == membuff){
		return NULL;
	}

	coroutine_t* rt = (coroutine_t*)calloc(1, sizeof(coroutine_t));
	if(NULL == rt){
		free(membuff);
		return NULL;
	}

	coctx_init(&(rt->ctx));
	rt->ctx.ss_size = size;
	rt->ctx.ss_sp = membuff;

	rt->pfn = pfn;
	rt->arg1 = arg1;
	rt->arg2 = arg2;

	rt->pfn_recycle = precyle;
	rt->recycler = recycler;

	/*
	rt->start = 0;
	rt->end = 0;

	rt->pre = NULL;
	
	rt->params = NULL;
	rt->size = 0;
	*/

	INIT_LIST_HEAD(&(rt->free_list));
	INIT_LIST_HEAD(&(rt->req_co_timeout_wheel));

	return rt;
}

static int co_routine_func(coroutine_t* co, void*)
{
	if(co->pfn){
		co->pfn(co->arg1, co->arg2);
	}

	//printf("co:%llu end\n", (size_t)co);
	co->end = 1;

	co_yield(co);
	return 0;
}

void co_resume(coroutine_t* routine)
{
	if(NULL == routine || !routine->pre){
		return;
	}

	if(!routine->start){
		coctx_make(&routine->ctx, (coctx_pfn_t)co_routine_func, routine, NULL);
		routine->start = 1;
	}

	co_swap(routine->pre, routine);
}

void co_yield(coroutine_t* curr)
{
	if(NULL == curr || !curr->pre){
		return;
	}

	co_swap(curr, curr->pre);
}

void co_release(coroutine_t** routine)
{
	if(NULL == routine || NULL == (*routine)){
		return;
	}

	if(!((*routine)->end)){
		return;
	}

	if((*routine)->pfn_recycle){
		fn_co_recycle fn = (*routine)->pfn_recycle;
		void* recycler = (*routine)->recycler;
		fn(recycler, *routine);
		return;
	}

	co_destroy(routine);
}

void co_free_batch_rslt_list(coroutine_t* co)
{
	list_head* p = NULL;
	list_head* next = NULL;
	list_for_each_safe(p, next, &co->batch_rslt_list){
		batch_rpc_result_t* bt = list_entry(p, batch_rpc_result_t, batch_rslt);
		list_del(p);
		free(bt);
	}
}

void co_destroy(coroutine_t** routine)
{
	if(NULL == routine || NULL == (*routine)){
		return;
	}

	coroutine_t* co = *routine;
	if(co->ctx.ss_sp)
		free(co->ctx.ss_sp);

	co_free_batch_rslt_list(co);

	free(co);
	*routine = NULL;
}

static void co_swap(coroutine_t* curr, coroutine_t* next)
{
	coctx_swap(&curr->ctx, &next->ctx);
}

void add_batch_rsp_rslt(coroutine_t* co)
{
	if(!is_co_in_batch_mode(co)){
		return;
	}
	batch_rpc_result_t* rslt = (batch_rpc_result_t*)calloc(1, sizeof(batch_rpc_result_t));
	INIT_LIST_HEAD(&rslt->batch_rslt);
	list_add_tail(&rslt->batch_rslt, &co->batch_rslt_list);
}

batch_rpc_result_t* get_co_last_req_rslt(coroutine_t* co)
{
	if(!is_co_in_batch_mode(co)){
		return NULL;
	}
	if(list_empty(&co->batch_rslt_list)){
		return NULL;
	}

	list_head* tail = co->batch_rslt_list.prev;
	batch_rpc_result_t* rslt = list_entry(tail, batch_rpc_result_t, batch_rslt);
	return rslt;
}

batch_rpc_result_t* get_co_req_rslt_by_req_id(coroutine_t* co, uint64_t ss_req_id)
{
	if(!is_co_in_batch_mode(co)){
		return NULL;
	}

	list_head* p = NULL;
	list_for_each(p, &co->batch_rslt_list){
		batch_rpc_result_t* rslt = list_entry(p, batch_rpc_result_t, batch_rslt);
		if(rslt->req_id == ss_req_id){
			return rslt;
		}
	}

	return NULL;
}

static void recycle_co(void* recycler, coroutine_t* co)
{
	if(NULL == co->ptr_list.next || NULL == co->ptr_list.prev){
		LOG_ERR("co ptr_list same error");
		INIT_LIST_HEAD(&co->ptr_list);
	}else{
		list_del(&co->ptr_list);
		INIT_LIST_HEAD(&co->ptr_list);
	}

	if(co->proto_user_ctx){
		delete ((blink::UserContext*)co->proto_user_ctx);
		co->proto_user_ctx = NULL;
	}

	if(co->batch_mode){
		co->batch_mode = 0;
		co->batch_req_num = 0;
		co_free_batch_rslt_list(co);
	}

	list_del(&(co->free_list));
	INIT_LIST_HEAD(&co->free_list);

	worker_thread_t* worker = (worker_thread_t*)recycler;
	del_timeout_event_from_timer(&(worker->timers), &(co->req_co_timeout_wheel));

	list_del(&(co->async_req_out_list));
	INIT_LIST_HEAD(&(co->async_req_out_list));
	co->async_cli_ptr= NULL;

	if(co->json_req_root){
		json_object_put((json_object*)(co->json_req_root));
	}
	co->json_swoole_response = NULL;
	co->json_req_root = NULL;
	co->json_swoole_body_head = NULL;
	co->json_swoole_body_body = NULL;
	co->json_swoole_body_http = NULL;
	co->json_swoole_body_data = NULL;

	if(worker->num_free_co >= K_CO_CACHE_NUM){
		--worker->num_alloc_co;
		co_destroy(&co);
		return;
	}

	co->pfn = NULL;
	co->arg1 = NULL;
	co->arg2 = NULL;

	//co->pfn_recycle = NULL;
	//co->recycler = NULL;

	co->start = 0;
	co->end = 0;

	co->pre = NULL;

	co->params = NULL;
	co->size = 0;

	co->hash_key = 0;
	co->cmd_id = 0;
	co->cli_req_id = 0;
	co->ss_req_id = 0;
	co->sys_code = 0;
	co->err_msg[0] = 0;
	co->uctx.ss_trace_id = 0;
	co->uctx.ss_trace_id_s[0] = 0;
	co->ptr_closed = 0;

	//co->swoole_head = NULL;
	memset(co->swoole_head, 0, sizeof(swoole_head_t));


	list_add(&(co->free_list), &(worker->free_co_list));
	++worker->num_free_co;
}

coroutine_t* get_co_ctx(worker_thread_t* worker, fn_method fn)
{
	coroutine_t* co = NULL;
	if(!list_empty(&(worker->free_co_list))){
		list_head* p = pop_list_node(&(worker->free_co_list));
		co = list_entry(p, coroutine_t, free_list);
		co->pfn =(fn_co_routine)fn;
		--worker->num_free_co;
	}else{
		co = co_create((fn_co_routine)fn, NULL, NULL, recycle_co, worker);
		if(NULL == co)
			return NULL;
		++worker->num_alloc_co;
	}

	INIT_LIST_HEAD(&co->ptr_list);
	INIT_LIST_HEAD(&co->async_req_out_list);

	co->batch_mode = 0;
	co->batch_req_num = 0;
	INIT_LIST_HEAD(&co->batch_rslt_list);

	co->async_cli_ptr = NULL;
	memset(&(co->uctx), 0, sizeof(co->uctx));

	co->arg1 = worker;
	co->arg2 = co;

	co->worker = worker;
	co->timeout = 0;

	return co;
}

coroutine_t* get_co_by_req_id(ev_ptr_t* ptr, uint64_t req_id)
{
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	return (coroutine_t*)util_get_item(worker->co_cache, &req_id, sizeof(req_id));
}

void do_fin_request(coroutine_t* co)
{
	co->timeout = 0;
	if(co && co->async_cli_ptr){
		list_del(&(co->async_req_out_list));
		INIT_LIST_HEAD(&(co->async_req_out_list));
		if(!is_co_in_batch_mode(co)){
			ev_ptr_t* ptr = (ev_ptr_t*)co->async_cli_ptr;
			--(ptr->num_async_out);
		}

		LOG_DBG("request to finished traceid:%llu, ss_seq_id:%llu, finished. num async out:%d", co->uctx.ss_trace_id, co->cache_req_id, ((ev_ptr_t*)co->async_cli_ptr)->num_async_out);
	}
}

void save_batch_co(coroutine_t* co, ev_ptr_t* ptr, const char* service, int method, uint64_t ss_req_id)
{
	if(is_co_in_batch_mode(co) && co->wait_reply){
		add_batch_rsp_rslt(co);
		batch_rpc_result_t* rslt = get_co_last_req_rslt(co);
		rslt->req_id = ss_req_id;
		//strncpy(rslt->service, service, sizeof(rslt->service)-1);
		//rslt->method = method;
		strncpy(rslt->rpc_info.ip, ptr->ip, sizeof(rslt->rpc_info.ip));
		rslt->rpc_info.start_time = co->rpc_info.start_time;

		++co->batch_req_num;
		rslt->ptr = ptr;
		rslt->finish = 0;
		rslt->ts = get_milli_second();
	}
}

void chg_co_timeout(coroutine_t* co, ev_ptr_t* cli)
{
	if((!co->timeout) && cli->cli){
		co->timeout = cli->cli->timeout;
	}
}

int prepare_co_before_async_call(coroutine_t* co, ev_ptr_t* cli)
{
	if(co){
		co->async_cli_ptr = NULL;
		if(co->async_req_out_list.next && co->async_req_out_list.prev)
			list_del(&(co->async_req_out_list));
		INIT_LIST_HEAD(&(co->async_req_out_list));
	}

	if(co && co->wait_reply && cli->cli->req_queue_size && cli->num_async_out > cli->cli->req_queue_size){
		LOG_ERR("request to %s:%d fd:%d too many. num:%d:%d", cli->ip, cli->port, cli->fd, cli->num_async_out, cli->cli->req_queue_size);
		return blink::EN_MSG_RET_SYSTEM_BUSY;
	}

	if(!is_co_in_batch_mode(co)){
		co->rpc_info.start_time = get_milli_second();
		strncpy(co->rpc_info.ip, cli->ip, sizeof(co->rpc_info.ip));
	}

	return 0;
}

void add_co_to_async_list(worker_thread_t* worker, coroutine_t* co, ev_ptr_t* cli)
{
	++cli->num_async_out;
	list_del(&(co->async_req_out_list));
	list_add(&(co->async_req_out_list), &(cli->async_req_out_list));
	co->async_cli_ptr = cli;

	LOG_DBG("set req. worker%llu , traceid:%s, ss_req_id:%llu host:%s:%d num_request:%d", (long long unsigned)worker, co->uctx.ss_trace_id_s, co->cache_req_id, cli->ip, cli->port, cli->num_async_out);
}

void begin_batch_request(coroutine_t* co)
{
	co->timeout = 0;
	co->batch_mode = 1;
	co->rpc_info.start_time = get_milli_second();
	add_batch_trace_point(co);
}

void end_batch_request(coroutine_t* co)
{
	if(!is_co_in_batch_mode(co)){
		return;
	}

	fill_batch_trace_point_cost(co);

	if(list_empty(&co->batch_rslt_list)){
		co->batch_mode = 0;
		return;
	}

	add_co_timeout_wheel((worker_thread_t*)(co->worker), co);

	struct timeval macro_start_val; 
	gettimeofday(&macro_start_val, NULL);

	co_yield(co);
	co->timeout = 0;

	struct timeval macro_end_val; 
	gettimeofday(&macro_end_val, NULL);
	int milli_cost = 1000*(macro_end_val.tv_sec-macro_start_val.tv_sec) +(macro_end_val.tv_usec-macro_start_val.tv_usec)/1000;
	LOG_DBG("batch request total milli_cost:%d", milli_cost);
	list_head* p;
	list_for_each(p, &co->batch_rslt_list){
		batch_rpc_result_t* rslt = list_entry(p, batch_rpc_result_t, batch_rslt);
		LOG_DBG("batch request call %s:%s %d, last sys_code:%d", rslt->rpc_info.service, rslt->rpc_info.method, rslt->sys_code, co->sys_code);
	}

	co->batch_mode = 0;
	co_free_batch_rslt_list(co);
}
