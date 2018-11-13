#include <server_inner.h>

static void save_co_body(coroutine_t* co, const blink::MsgBody& body);

static uint64_t gen_id(worker_thread_t* worker)
{
	do{
		uint64_t id = (worker->pb_co_id++);
		coroutine_t* co = (coroutine_t*)util_get_item(worker->co_cache, &id, sizeof(id));
		if(NULL == co){
			return id;
		}
	}while(1);
}

int process_pb_request(ev_ptr_t* ptr, const blink::MsgBody& body)
{
	const char* service = body.service().c_str(); 
	int method = body.method(); 
	const char* params = body.payload().c_str();
	size_t size = body.payload().size();

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	fn_method fn = get_fn_method(worker, service, method);
	if(NULL == fn){
		return 0;
	}

	coroutine_t* req_co = get_co_ctx(worker, fn);
	if(NULL == req_co){
		LOG_ERR("failed to get co ctx");
		return 0;
	}

	++worker->num_request;

	req_co->proto_user_ctx = new blink::UserContext();//body.uctx();
	init_proto_uctx((blink::UserContext*)(req_co->proto_user_ctx));
	if(body.has_uctx()){
		((blink::UserContext*)(req_co->proto_user_ctx))->CopyFrom(body.uctx());
		((blink::UserContext*)(req_co->proto_user_ctx))->clear_trace_points();
	}

	INIT_LIST_HEAD(&req_co->ptr_list);
	list_add(&req_co->ptr_list, &ptr->co_list);
	//printf("recv request add list:%llu\n", (size_t)req_co);

	req_co->arg1 = ptr;
	req_co->arg2 = req_co;

	req_co->params = params;
	req_co->size = size;
	req_co->pre = worker->wt_co;
	req_co->ptr_closed = 0;

	save_co_body(req_co, body);
	req_co->sys_code = 0;
	req_co->need_trace_point = body.need_trace_point();
	LOG_DBG("recv request. ss_req_id:%llu, co:%llu", req_co->ss_req_id, (long long unsigned)req_co);

	printf("resume coroutine\n");
	co_resume(req_co);
	printf("coroutine end\n");
	if(ptr->tmp){
		req_co->ptr_closed = 1;
	}
	co_release(&req_co);
	return 0;
}

static int process_pb_response(ev_ptr_t* ptr, const blink::MsgBody& body) 
{
	uint64_t ss_req_id = body.ss_req_id();
	coroutine_t* req_co = get_co_by_req_id(ptr, ss_req_id);
	if(NULL == req_co){
		LOG_ERR("failed to get req co. worker:%llu, req_id:%llu", (ptr->arg), body.ss_req_id());
		return 0;
	}

	if(body.err_code() < 0){
		fail_circuit_breaker(ptr->breaker);
	}else{
		succ_circuit_breaker(ptr->breaker);
	}

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	util_del_item(worker->co_cache, &ss_req_id, sizeof(ss_req_id));

	int milli_cost = 0;
	if(body.has_uctx() && body.uctx().trace_points_size()){
		int last  = body.uctx().trace_points_size() - 1;
		milli_cost = body.uctx().trace_points(last).milli_cost();
	}

	if(ptr->cli){
		int cpu_usage = body.cpu_usage()>100?100:body.cpu_usage();
		cpu_usage = cpu_usage<=0?0:cpu_usage;
		ptr->cli->weight = cpu_usage/2+1;
	}

	if(is_co_in_batch_mode(req_co)){
		batch_rpc_result_t* rslt = get_co_req_rslt_by_req_id(req_co, ss_req_id);
		if(NULL == rslt){
			LOG_ERR("no rslt for ss_req_id:%llu, traceid:%s", ss_req_id, req_co->uctx.ss_trace_id_s);
			return 0;
		}

		mc_collect(worker, &rslt->rpc_info, milli_cost, body.err_code(), 1, req_co->uctx.ss_trace_id_s);
		append_trace_point(req_co, &rslt->rpc_info, &body.uctx(), body.err_code());

		rslt->finish = 1;
		rslt->sys_code = body.err_code();
		if(rslt->rsp){
			rslt->rsp->ParseFromArray(body.payload().c_str(), body.payload().size());
		}

		if(ptr == (ev_ptr_t*)(rslt->ptr)){
			--(ptr->num_async_out);
		}

		--req_co->batch_req_num;

		LOG_DBG("worker:%llu, traceid:%s, request to %s:%d fd:%d ss_seq_id:%llu, finished. num async out:%d, remain batch_req_num:%d, service:%s, cost_time:%llums", \
		(unsigned long long)worker, req_co->uctx.ss_trace_id_s, ptr->ip, ptr->port, ptr->fd, ss_req_id, ptr->num_async_out, req_co->batch_req_num, rslt->rpc_info.service, get_milli_second()-rslt->ts);
		if(req_co->batch_req_num){
			return 0;
		}
	}else{
		mc_collect(worker, &req_co->rpc_info, milli_cost, body.err_code(), 0, req_co->uctx.ss_trace_id_s);
		append_trace_point(req_co, &req_co->rpc_info, &body.uctx(), body.err_code());
	}

	do_fin_request(req_co);
	del_timeout_event_from_timer(&(worker->timers), &(req_co->req_co_timeout_wheel));

	req_co->pre = ((worker_thread_t*)(ptr->arg))->wt_co;
	req_co->sys_code = body.err_code();

	req_co->params = body.payload().c_str();
	req_co->size = body.payload().size();

	req_co->sys_code = body.err_code();
	//req_co->err_msg = body.err_msg().data();
	req_co->err_msg[0] = 0;
	if(body.has_err_msg()){
		strncpy(req_co->err_msg, body.err_msg().data(), sizeof(req_co->err_msg)-1);
	}

	co_resume(req_co);
	co_release(&req_co);
	return 0;
}

int process_pb_request_from_ev_ptr(ev_ptr_t* ptr)
{
	blink::MsgHead head;
	init_msg_head(head);

	int rc = 0;
	while(util_get_rd_buff_len(ptr->recv_chain) >= head.ByteSize()){
		rc = util_parse_pb_from_buff(head, ptr->recv_chain, head.ByteSize());
		if(rc < 0){
			LOG_ERR("failed to parse head from buff");
			return -1;
		}
		if(rc > 0){
			LOG_DBG("need more data");
			return 0;
		}

		if((unsigned)util_get_rd_buff_len(ptr->recv_chain) <(unsigned) (head.ByteSize() + head.len())){
            //LOG_INFO("need more data xxxxxxxxxxxxx:total:%llu, current:%u", head.ByteSize()+head.len(), (unsigned)util_get_rd_buff_len(ptr->recv_chain));
			return 0;
		}

		util_advance_rd(ptr->recv_chain, head.ByteSize());
		if(0 == head.len()){
			if(!ptr->cli){
				LOG_DBG("recv heartbeat from:%d", ptr->fd);
				async_pb_heartbeat((worker_thread_t*)ptr->arg, ptr);
			}
			//return 0;
			continue;
		}

		blink::MsgBody body;
		rc = util_parse_pb_from_buff(body, ptr->recv_chain, head.len());
		if(rc < 0){
			LOG_ERR("failed to parse body");
			return -2;
		}
		if(rc > 0){
			LOG_DBG("impossible here, need more data");
		}

        //LOG_INFO("recv a full package:ss_seq_id:%llu", body.ss_req_id());
		util_advance_rd(ptr->recv_chain, head.len());
		if(body.call_type() == blink::EN_MSG_TYPE_RESPONSE){
			rc = process_pb_response(ptr, body);
		}else{
			rc = process_pb_request(ptr, body);//
		}

		if(rc){
			return -3;
		}
	}

	return 0;
}

static void save_co_body(coroutine_t* co, const blink::MsgBody& body)
{
	if(!co) return;

	co->cmd_id = body.cmd();
	co->cli_req_id = body.cli_req_id();
	co->session_code = body.session_code();
	//co->uid = body.uid();
	co->ss_req_id = body.ss_req_id();
	co->sys_code = body.err_code();
	co->uctx.flag_test = 0;

	if(body.has_uctx()){
		co->uctx.uid = body.uctx().uid();
		strncpy(co->uctx.cli_ip, body.uctx().cli_ip().c_str(), sizeof(co->uctx.cli_ip));
		strncpy(co->uctx.conn_ip, body.uctx().conn_ip().c_str(), sizeof(co->uctx.conn_ip));
		co->uctx.conn_port = (unsigned short)body.uctx().conn_port();
		strncpy(co->uctx.platform, body.uctx().platform().c_str(), sizeof(co->uctx.platform));
		co->uctx.dev_type = body.uctx().dev_type();
		co->uctx.dev_crc32 = body.uctx().dev_crc32();
		co->uctx.flag_test = body.uctx().flag_test();
	}

	co->uctx.ss_trace_id = body.uctx().ss_trace_id();
	if(body.uctx().ss_trace_id_s().size()){
		strncpy(co->uctx.ss_trace_id_s, body.uctx().ss_trace_id_s().data(), sizeof(co->uctx.ss_trace_id_s) - 1);
		co->uctx.ss_trace_id = strtoul(co->uctx.ss_trace_id_s, NULL, 10);
	}else if(co->uctx.ss_trace_id){
		snprintf(co->uctx.ss_trace_id_s, sizeof(co->uctx.ss_trace_id_s) - 1, "%" PRIu64, co->uctx.ss_trace_id);
	}else{
		co->uctx.ss_trace_id = (co->uctx.uid<<32)|time(NULL)|(random());
		snprintf(co->uctx.ss_trace_id_s, sizeof(co->uctx.ss_trace_id_s) - 1, "%" PRIu64, co->uctx.ss_trace_id);
	}

	LOG_DBG("uid:%llu, cli_ip:%s platform:%s conn_ip:%s conn_port:%d dev_type:%d, traceid:%s", co->uctx.uid, co->uctx.cli_ip, co->uctx.platform, co->uctx.conn_ip, co->uctx.conn_port, co->uctx.dev_type, co->uctx.ss_trace_id_s);
}

void async_pb_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr)
{
	blink::MsgHead head;
	init_msg_head(head);

	int rc = util_serialize_pb_to_buff(head, ptr->send_chain);
	if(rc){
		return;
	}

	LOG_DBG("send heart beat to pb service. worker:%llu %s:%d fd:%d", (unsigned long long)worker, ptr->ip, ptr->port, ptr->fd);
	ptr->do_write_ev = do_write_msg_to_tcp;
	add_write_ev(worker->epoll_fd, ptr);
	do_write_msg_to_tcp(ptr);
}

int serialize_pb_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg) 
{
	std::string* str_msg = new std::string();
	if(msg)
		msg->SerializeToString(str_msg);
	int rc = serialize_buff_to_send_chain(ptr, co, ret_code, str_msg->c_str(), str_msg->size(), err_msg);
	//LOG_INFO("send buff size:%llu", str_msg->size());
	delete str_msg;

	return rc;
}

int serialize_buff_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, const char* buf, size_t size, const char* err_msg)
{
	LOG_DBG("response to ss_req_id:%llu co:%llu to:%s:%d", co->ss_req_id, (long long unsigned)co, ptr->ip, ptr->port);
	blink::MsgBody body;
	body.set_call_type(blink::EN_MSG_TYPE_RESPONSE);
	body.set_err_code(ret_code);
	body.set_ss_req_id(co->ss_req_id);
    body.set_cli_req_id(co->cli_req_id);
	body.set_cmd(co->cmd_id);
	body.set_cpu_usage(((worker_thread_t*)(co->worker))->cpu_usage);
	if(err_msg)body.set_err_msg(err_msg);

	if(co->proto_user_ctx && ptr && ptr->listen && (!(((listen_t*)ptr->listen)->tag&1))){
		body.mutable_uctx()->CopyFrom(*((blink::UserContext*)(co->proto_user_ctx)));
	}

	body.set_payload(buf, size);
	body.set_need_trace_point(co->need_trace_point);

	blink::MsgHead head;
	init_msg_head(head);
	head.set_len(body.ByteSize());

	int rc = util_serialize_pb_to_buff(head, ptr->send_chain);
	if(rc){
		LOG_ERR("failed to add rsp head to chain");
		return -1;
	}

	rc = util_serialize_pb_to_buff(body, ptr->send_chain);
	if(rc){
		util_advance_rd(ptr->send_chain, head.ByteSize());
		LOG_ERR("failed to add rsp body to chain");
		return -2;
	}

	return 0;
}

int async_req_with_pb_msg(worker_thread_t* worker, coroutine_t* co, const char* service, int method, ::google::protobuf::Message* msg, int timeout)
{
	std::string* str_msg = new std::string();
	if(NULL != msg){
		msg->SerializeToString(str_msg);
	}

	co->timeout = timeout;
	int rc = async_req_with_pb_buff(worker, co, service, method, str_msg->c_str(), str_msg->size());
	delete str_msg;

	return rc;
}

static void set_user_ctx(coroutine_t* co, blink::MsgBody* body)
{
	if(!co || !body)return;

	blink::UserContext* ctx = body->mutable_uctx();
	//if(co->proto_user_ctx)
		//ctx->CopyFrom(*((blink::UserContext*)(co->proto_user_ctx)));

	ctx->set_uid(co->uctx.uid);
	ctx->set_cli_ip(co->uctx.cli_ip);
	ctx->set_conn_ip(co->uctx.conn_ip);
	ctx->set_platform(co->uctx.platform);
	ctx->set_conn_port(co->uctx.conn_port);
	ctx->set_dev_type(co->uctx.dev_type);
	ctx->set_ss_trace_id(co->uctx.ss_trace_id);
	ctx->set_ss_trace_id_s(co->uctx.ss_trace_id_s);
	ctx->set_dev_crc32(co->uctx.dev_crc32);
	ctx->set_flag_test(co->uctx.flag_test);
}

static int __async_write_pb_buff(worker_thread_t* worker, ev_ptr_t* cli, coroutine_t* co, const char* service, int method, const char* msg, size_t size)
{
	int rc = prepare_co_before_async_call(co, cli);
	if(rc){
		return rc;
	}

	co->err_msg[0] = 0;

	//worker_thread_t* worker = (worker_thread_t*)ptr->arg;
	uint64_t ss_req_id = gen_id(worker);

	blink::MsgBody body;
	body.set_call_type(blink::EN_MSG_TYPE_REQUEST);
	body.set_err_code(0);
	body.set_ss_req_id(ss_req_id);

	body.set_service(service);
	body.set_method(method);
	body.set_need_trace_point(co->need_trace_point);

	body.set_payload(msg, size);
	set_user_ctx(co, &body);

	blink::MsgHead head;
	init_msg_head(head);
	head.set_len(body.ByteSize());

	if(!cli->udp_sock){
		rc = util_serialize_pb_to_buff(head, cli->send_chain);
	}

	if(rc){
		LOG_ERR("failed to add rsp head to chain");
		return -2;
	}

	rc = util_serialize_pb_to_buff(body, cli->send_chain);
	if(rc){
		LOG_ERR("failed to add rsp body to chain");
		return -3;
	}

	if(co && co->wait_reply){
		co->cache_req_id= ss_req_id;
		util_set_item(worker->co_cache, &ss_req_id, sizeof(ss_req_id), co, NULL);
		add_co_to_async_list(worker, co, cli);
	}

	cli->do_write_ev = do_write_msg_to_tcp;
	add_write_ev(worker->epoll_fd, cli);
	do_write_msg_to_tcp(cli);

	save_batch_co(co, cli, service, method, ss_req_id);

	return 0;
}

int async_req_with_pb_buff(worker_thread_t* worker, coroutine_t* co, const char* service, int method, const char* msg, size_t size)
{
	ev_ptr_t* cli = get_cli_ptr(worker, co, service);
	if(NULL == cli){
		LOG_ERR("no client for service:%s", service);
		return -1;
	}

	chg_co_timeout(co, cli);
	return __async_write_pb_buff(worker, cli, co, service, method, msg, size);
}

int async_req_pb_2_ip(worker_thread_t* worker, coroutine_t* co, const char* service, int method, const char* ip, int port, ::google::protobuf::Message* msg)
{
	if(NULL == service || NULL == msg){
		LOG_ERR("null service or msg");
		return -1;
	}

	ev_ptr_t* cli = get_cli_ptr_by_ip(worker, service, ip, port);
	if(NULL == cli){
		LOG_ERR("failed to get connect to %s:%d(service:%s)", ip, port, service);
		return -2;
	}

	chg_co_timeout(co, cli);
	std::string str_msg;
	msg->SerializeToString(&str_msg);
	return __async_write_pb_buff(worker, cli, co, service, method, str_msg.c_str(), str_msg.size());
}

void init_msg_head(blink::MsgHead& head)
{
	head.set_len(0);
	head.set_crc(K_PB_MAGIC);
	//head.set_magic(K_PB_MAGIC);
}

