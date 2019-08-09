#include <server_inner.h>
#include <sys/epoll.h>
#include <http2_client.h>

#define K_HEART_BEAT_INTERVAL 15
#define K_EV_PTR_CACHE_NUM 0 

void add_co_timeout_wheel(worker_thread_t* worker, coroutine_t* co)
{
	if(!(co->timeout) || co->timeout > K_MAX_TIMEOUT*1000){
		co->timeout = 1600;
	}

	add_timeout_event_2_timer(&worker->timers, co->timeout, &(co->req_co_timeout_wheel), &(co->req_co_milli_offset));
}

void add_client_inst_2_wheel(worker_thread_t* worker, proto_client_inst_t* cli)
{
	size_t interval  = 2000;
	++(cli->num_conn_failed);
	add_disconnect_event_2_timer(&(worker->timers), interval, &(cli->disconnected_client_wheel),&(cli->disconnect_milli_offset));
	LOG_INFO("worker:%llu add host:%s:%d to reconnect wheel", (long long unsigned)worker, cli->ip, cli->port);
}

void add_ev_ptr_2_heartbeat_wheel(worker_thread_t* worker, ev_ptr_t* ptr)
{
	if(NULL == ptr){
		return;
	}

	if(!ptr->cli){
		return;
	}

	add_heartbeat_event_2_timer(&(worker->timers), K_HEART_BEAT_INTERVAL*1000, &(ptr->heartbeat_wheel), &(ptr->heartbeat_milli_offset));
	LOG_DBG("worker:%llu add host:%s:%d fd:%d to heartbeat wheel", (long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
}

void add_ev_ptr_2_idle_time_wheel(worker_thread_t* worker, ev_ptr_t* ptr)
{
	if(ptr->idle_time == 0 || ptr->idle_time > K_MAX_TIMEOUT){
		ptr->idle_time = K_DEFALUT_IDLE_TIME;
	}

	add_idle_event_2_timer(&(worker->timers), ptr->idle_time*1000, &(ptr->idle_time_wheel), &(ptr->idle_milli_offset));
	LOG_DBG("worker:%llu add host:%s:%d fd:%d to idle time wheel", (long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
}

void recycle_ev_ptr(ev_ptr_t* ptr)
{
	if(NULL == ptr){ 
		return;
	}

	free_circuit_breaker(ptr->breaker);
	ptr->breaker = NULL;

	list_head* p;
	list_head* next;
	//for accept ptr
	list_for_each_safe(p, next, &ptr->co_list){
		coroutine_t* co = list_entry(p, coroutine_t, ptr_list);
		co->ptr_closed = 1;
		list_del(p);
		INIT_LIST_HEAD(p);
	}

	//for connect ptr
	p = next = NULL;
	list_for_each_safe(p, next, &ptr->async_req_out_list){
		coroutine_t* co = list_entry(p, coroutine_t, async_req_out_list);
		list_del(&(co->async_req_out_list));
		INIT_LIST_HEAD(&(co->async_req_out_list));
		co->async_cli_ptr = NULL;
	}

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(!ptr->epoll_del){
		struct epoll_event ev;
		epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, ptr->fd, &ev);
		ptr->epoll_del = 1;
	}

	del_heartbeat_event_from_timer(&worker->timers, &(ptr->heartbeat_wheel));
	del_idle_event_from_timer(&worker->timers, &(ptr->idle_time_wheel));

	if(ptr->recv_chain){
		util_destroy_buff_chain(ptr->recv_chain);
		ptr->recv_chain = NULL;
	}

	if(ptr->send_chain){
		util_destroy_buff_chain(ptr->send_chain);
		ptr->send_chain = NULL;
	}

	//if(ptr->recv_chain) util_reset_buff_chain(ptr->recv_chain);
	//if(ptr->send_chain) util_reset_buff_chain(ptr->send_chain);

	if(ptr->cli){
		LOG_DBG("add_client_inst_2_wheel worker:%llu fd:%llu host:%s:%d", (long long unsigned)worker, ptr->fd, ptr->cli->ip, ptr->cli->port);
		add_client_inst_2_wheel(worker, ptr->cli);
		ptr->cli->ptr = NULL;
	}

	util_del_item(worker->ev_ptr_cache, &(ptr->fd), sizeof(ptr->fd));
	if(worker->num_free_ev_ptr >= K_EV_PTR_CACHE_NUM){
		--worker->num_alloc_ev_ptr;
		free(ptr);
		return;
	}

	//util_recycle_block_to_pool(worker->ev_ptr_pool, ptr);
	ptr->ev = 0;
	ptr->fd = 0;
	ptr->arg = NULL;
	ptr->epoll_del = 0;
	ptr->process_handler = NULL;
	ptr->no_cb = 0;
	ptr->udp_sock = 0;
	ptr->listen = NULL;
	ptr->cli = NULL;
	ptr->num_async_out = 0;
	++worker->num_free_ev_ptr;
	list_add(&ptr->free_ev_ptr_list, &worker->free_ev_ptr_list);
}

void shut_down_ev_ptr(ev_ptr_t* ptr)
{
	if(NULL == ptr){
		LOG_ERR("NULL ptr, impossible");
		return;
	}

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(NULL == worker){
		LOG_ERR("NULL worker, impossible");
		return;
	}

	//worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(worker->wt_fns.do_shutdown_conn &&(!(ptr->no_cb))){
		(worker->wt_fns.do_shutdown_conn)(worker, ptr->fd);
	}

	struct epoll_event ev;
	epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, ptr->fd, &ev);
	ptr->epoll_del = 1;

	close(ptr->fd);

	if(!ptr->cli)
		--worker->conns;
}

void add_read_ev(int epoll_fd, ev_ptr_t* ptr)
{
	uint32_t pre_ev = (NULL == ptr?0:ptr->ev);
	int op = (pre_ev == 0?EPOLL_CTL_ADD:EPOLL_CTL_MOD);

	struct epoll_event ev;
	ev.events = EPOLLIN|pre_ev;
	ptr->ev = ev.events;
	ptr->epoll_del = 0;
	
	ev.data.ptr = ptr;
	epoll_ctl(epoll_fd, op, ptr->fd, &ev);
}

void add_write_ev(int epoll_fd, ev_ptr_t* ptr)
{
	if(ptr->fd == 0){
		return;
	}

	uint32_t pre_ev = (NULL == ptr?0:ptr->ev);
	int op = (pre_ev == 0?EPOLL_CTL_ADD:EPOLL_CTL_MOD);

	struct epoll_event ev;
	ev.events = EPOLLOUT|pre_ev;
	ptr->ev = ev.events;
	ptr->epoll_del = 0;

	ev.data.ptr = ptr;
	epoll_ctl(epoll_fd, op, ptr->fd, &ev);
}

void cancel_write_ev(int epoll_fd, ev_ptr_t* ptr)
{
	if(!ptr || !(ptr->ev & EPOLLOUT)){
		return;
	}

	int op = EPOLL_CTL_DEL;
	uint32_t pre_ev = ptr->ev;
	if(pre_ev & EPOLLIN){
		op = EPOLL_CTL_MOD;
	}

	if(op == EPOLL_CTL_DEL){
		ptr->epoll_del = 1;
		LOG_INFO("del from epoll. fd:%d", ptr->fd);
	}

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = ptr;
	epoll_ctl(epoll_fd, op, ptr->fd, &ev);
}

void init_user_context(blink::UserContext* usr_ctx, const rpc_info_t* info, int cost, int err_code)
{
	if(!usr_ctx || usr_ctx->trace_points_size()){
		return;
	}

	uint64_t now = get_milli_second();
	blink::TracePoint* p = usr_ctx->add_trace_points();
	p->set_service(info->service);
	p->set_method(info->method);
	p->set_ip(info->ip);
	p->set_milli_cost(cost);
	p->set_err_code(err_code);
	p->set_caller_rcv_ts(now);
	p->set_caller_cost(now - info->start_time);
}

void do_check_co_timeout(worker_thread_t* worker, list_head* node)
{
	list_del(node);
	INIT_LIST_HEAD(node);

	blink::UserContext user_ctx;
	coroutine_t* co = list_entry(node, coroutine_t, req_co_timeout_wheel);
	LOG_ERR("request is timeout.worker:%llu, traceid:%s, ss_req_id:%llu", (long long unsigned)worker, co->uctx.ss_trace_id_s, co->cache_req_id);
	if(is_co_in_batch_mode(co)){
		list_head* p;
		list_for_each(p, &co->batch_rslt_list){
			batch_rpc_result_t* rslt = list_entry(p, batch_rpc_result_t, batch_rslt);
			if(rslt->finish){
				continue;
			}

			mc_collect(worker, &rslt->rpc_info, 5000, -2, 1, co->uctx.ss_trace_id_s);
			init_user_context(&user_ctx, &rslt->rpc_info, 5000, blink::EN_MSG_RET_TIMEOUT);
			append_trace_point(co, &rslt->rpc_info, &user_ctx, blink::EN_MSG_RET_TIMEOUT);

			util_del_item(worker->co_cache, &(rslt->req_id), sizeof(rslt->req_id));
			ev_ptr_t* ptr = (ev_ptr_t*)(rslt->ptr);
			co->sys_code = -22;
			rslt->sys_code = -22;
			proto_client_t* client = get_clients_by_service(worker, rslt->rpc_info.service);
			for(size_t i = 0; client && i < client->num_clients; ++i){
				proto_client_inst_t* inst = client->cli_inst_s + i;
				if(inst->ptr == ptr){
					--(ptr->num_async_out);
					--co->batch_req_num;
					fail_circuit_breaker(ptr?ptr->breaker:NULL);
					break;
				}
			}
		}

		//co_free_batch_rslt_list(co);
	}else{
		mc_collect(worker, &co->rpc_info, co->timeout, -2, 0, co->uctx.ss_trace_id_s);
		init_user_context(&user_ctx, &co->rpc_info, co->timeout, blink::EN_MSG_RET_TIMEOUT);
		append_trace_point(co, &co->rpc_info, &user_ctx, blink::EN_MSG_RET_TIMEOUT);
		proto_client_t* client = get_clients_by_service(worker, co->rpc_info.service);

		for(size_t i = 0; client && i < client->num_clients; ++i){
			proto_client_inst_t* inst = client->cli_inst_s + i;
			if(inst->ptr == co->async_cli_ptr){
				fail_circuit_breaker(co->async_cli_ptr?((ev_ptr_t*)(co->async_cli_ptr))->breaker:NULL);
				break;
			}
		}
	}

	uint64_t req_id = co->cache_req_id;
	util_del_item(worker->co_cache, &(req_id), sizeof(req_id));

	co->sys_code = blink::EN_MSG_RET_TIMEOUT;
	co->pre = worker->wt_co;

	do_fin_request(co);

	printf("req timeout:%lu\n", co->cache_req_id);
	co_resume(co);
	printf("req timeout:%lu resume finish\n", co->cache_req_id);
	co_release(&co);
}

void do_check_heartbeat_timeout(worker_thread_t* worker, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);

	ev_ptr_t* hb = list_entry(p, ev_ptr_t, heartbeat_wheel);
	async_heartbeat(worker, hb);
	LOG_DBG("add_ev_ptr_2_heartbeat_wheel times up. worker:%llu, host:%s:%d fd:%d", (long long unsigned)worker, hb->ip, hb->port, hb->fd);
	add_ev_ptr_2_heartbeat_wheel(worker, hb);
	return;
}

void do_check_idle_timeout(worker_thread_t* worker, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);

	ev_ptr_t* it  = list_entry(p, ev_ptr_t, idle_time_wheel);
	LOG_ERR("idle_time timer, worker:%llu recycle_ev_ptr host:%s:%d fd:%d",(long long unsigned)worker, it->ip, it->port, it->fd);
	if(it->process_handler == http2_ping_mark){
		clean_http2_cli((worker_thread_t*)it->arg, it->cli);
		return;
	}

	shut_down_ev_ptr(it);
	recycle_ev_ptr(it);
	return;
}

void do_check_disconnect_timeout(worker_thread_t* worker, list_head* p)
{
	list_del(p);
	INIT_LIST_HEAD(p);
	proto_client_inst_t* cli = list_entry(p, proto_client_inst_t, disconnected_client_wheel);
	LOG_ERR("timer do reconnect: worker:%llu, %s:%d", (long long unsigned)worker, cli->ip, cli->port);
	//TODO CAUTION, this would be blocked
	//init_client_inst(worker, cli, std::pair<char*, int>(cli->ip, cli->port));
	async_conn_server(worker, cli);
	//TODO
	return;
}

ev_ptr_t* get_ev_ptr(worker_thread_t* worker,int fd)
{
	ev_ptr_t* ptr = (ev_ptr_t*)util_get_item(worker->ev_ptr_cache, &fd, sizeof(fd));
	if(ptr) {
		LOG_INFO("get ptr from cache");
		return ptr;
	}

	if(!list_empty(&worker->free_ev_ptr_list)){
		list_head* p = pop_list_node(&(worker->free_ev_ptr_list));
		ptr = list_entry(p, ev_ptr_t, free_ev_ptr_list);
		--worker->num_free_ev_ptr;
		//return ptr;
	}else{
		ptr = (ev_ptr_t*)calloc(1, sizeof(ev_ptr_t));
		if(NULL == ptr){
			LOG_ERR("failed to calloc ev_ptr");
			return NULL;
		}
		++worker->num_alloc_ev_ptr;
	}

	//LOG_INFO("mem alloc worker:%llu, ev_ptr:%d", (long long unsigned)worker, worker->num_alloc_ev_ptr);

	INIT_LIST_HEAD(&(ptr->heartbeat_wheel));
	INIT_LIST_HEAD(&(ptr->idle_time_wheel));

	INIT_LIST_HEAD(&(ptr->co_list));
	INIT_LIST_HEAD(&ptr->free_ev_ptr_list);

	INIT_LIST_HEAD(&(ptr->async_req_out_list));

	ptr->fd = fd;
	util_set_item(worker->ev_ptr_cache, &fd, sizeof(fd), ptr, NULL);
	return ptr;
}

void clear_ev_ptr(ev_ptr_t* ptr)
{
	shut_down_ev_ptr(ptr);
	recycle_ev_ptr(ptr);
}

