#include <swoole_def.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <server_inner.h>

extern char* g_app_name;

static int write_req_2_swoole_server(ev_ptr_t* ptr, coroutine_t* co, uint32_t ss_req_id, const char* service, const char* method, ::google::protobuf::Message* msg, int version = 1, blink::UserContext* uctx = NULL);

void swoole_head_ntohl(swoole_head_t* head)
{
	if(NULL == head){
		return;
	}
	head->header_magic = ntohl(head->header_magic);
	head->header_ts= ntohl(head->header_ts);
	head->header_check_sum= ntohl(head->header_check_sum);
	head->header_version= ntohl(head->header_version);
	head->header_reserved = ntohl(head->header_reserved);
	head->header_seq = ntohl(head->header_seq);
	head->header_len = ntohl(head->header_len);
}

void swoole_head_htonl(swoole_head_t* head)
{
	if(NULL == head){
		return;
	}
	head->header_magic = htonl(head->header_magic);
	head->header_ts= htonl(head->header_ts);
	head->header_check_sum= htonl(head->header_check_sum);
	head->header_version= htonl(head->header_version);
	head->header_reserved = htonl(head->header_reserved);
	head->header_seq = htonl(head->header_seq);
	head->header_len = htonl(head->header_len);
}

void init_swoole_head(swoole_head_t* head, uint32_t version)
{
	if(NULL == head){
		return;
	}
	memset(head, 0, sizeof(swoole_head_t));
	head->header_magic = K_SWOOLE_MAGIC;
	head->header_ts = time(NULL);
	head->header_version = version;
}

void set_swoole_head_cmd(swoole_head_t* head, char type, const char* method)
{
	if(NULL == head){
		return;
	}

	if(NULL == method){
		return;
	}

	if(strlen(method)+1 >= sizeof(head->cmd)){
		return;
	}

	sprintf(head->cmd, "%c%s", type, method);
}

void pad_mem_with_iovecs(const std::vector<iovec>& iovs, char* mem, size_t need_len)
{
	size_t len = 0;
	for(size_t i = 0; i < iovs.size() && len < need_len; ++i){
		size_t copy_len = need_len -len>iovs[i].iov_len?iovs[i].iov_len:need_len-len;
		memcpy(mem+len, iovs[i].iov_base, copy_len);
		len += copy_len;
	}
}

uint32_t gen_32_id(worker_thread_t* worker)
{
	do{
		if(worker->swoole_co_id < 10){
			worker->swoole_co_id = 10;
		}

		uint32_t id = (worker->swoole_co_id)++;
		uint64_t up_id = id;
		coroutine_t* co = (coroutine_t*)util_get_item(worker->co_cache, &up_id, sizeof(up_id));
		if(NULL == co){
			return id;
		}
	}while(1);
}

fn_method get_swoole_fn_method(worker_thread_t* worker, const char* service, const char* method_name)
{
	size_t len = 0;
	const char* p = service;
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
		size_t len_service = strlen(svc->name);
		if(strncmp(svc->name, service, len) != 0 || len_service != len){
			continue;
		}

		if(len_service > 29){
			LOG_ERR("service name too long:%s", svc->name);
			continue;
		}

		size_t cmp_len = 30 - len_service;
		for(int i = 0; i < svc->num_methods; ++i){
			if(strncmp(svc->swoole_meth[i].method_name, method_name, cmp_len) == 0){
				return svc->swoole_meth[i].method;
			}
		}

		return NULL;
	}

	return NULL;
}

int process_swoole_request(ev_ptr_t* ptr, swoole_head_t* head, char* body)
{
	char* service = head->cmd + 1;
	char* method = service;
	while(*method != 0 && *method != '.'){
		++method;
	}
	if(*method == 0 || *(method+1) == 0){
		LOG_ERR("miss method:%s", head->cmd+1);
		return -1;
	}

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(strncmp(service, "ping.ping", 9) == 0){
		if(!ptr->cli)
			async_swoole_heartbeat(worker, ptr);
		return 0;
	}

	*method = 0;
	method += 1;
	fn_method fn = get_swoole_fn_method(worker, service, method);
	if(NULL == fn){
		LOG_ERR("no handler for %s.%s", service, method);
		return -1;
	}

	++worker->num_request;

	json_object* root = json_tokener_parse(body);
	if(NULL == root){
		LOG_ERR("invalid swoole body:%s", body);
		return -1;
	}

	json_object* header = NULL;
	if(!json_object_object_get_ex(root, "header", &header)){
		json_object_put(root);
		LOG_ERR("miss header in swoole body");
		return -2;
	}

	json_object* swoole_body = NULL;
	if(!json_object_object_get_ex(root, "body", &swoole_body)){
		json_object_put(root);
		LOG_ERR("miss body in swoole body");
		return -3;
	}

	json_object* swoole_http = NULL;
	if(!json_object_object_get_ex(root, "http", &swoole_http)){
		LOG_DBG("miss http in swoole body");
	}

	//json_object* swoole_ctx = NULL;
	//json_object_object_get_ex(root, "pb_svr", &swoole_ctx);

	int rc = do_process_swoole_request(worker, ptr, head, fn, root, header, swoole_body, swoole_http, NULL);
	if(rc){
		json_object_put(root);
	}

	return 0;
}

int do_process_swoole_request(worker_thread_t* worker, ev_ptr_t* ptr, swoole_head_t* head, fn_method fn, json_object* root, json_object* header, json_object* swoole_body, json_object* swoole_http, json_object* swoole_ctx)
{
	coroutine_t* req_co = get_co_ctx(worker, fn);
	if(NULL == req_co){
		return 1;
	}

	json_object* js_need_trace = NULL;
	json_object_object_get_ex(header, "need_trace", &js_need_trace);
	req_co->need_trace_point = js_need_trace?json_object_get_int(js_need_trace):0;

	req_co->proto_user_ctx = new blink::UserContext();
	init_proto_uctx((blink::UserContext*)(req_co->proto_user_ctx));

	json_object* js_uid = NULL;
	json_object_object_get_ex(header, "uid", &js_uid);
	uint64_t uid = js_uid?json_object_get_int64(js_uid):0;

	blink::SwooleBodyHeader sw_header;
	util_parse_pb_from_json(&sw_header, header);
	if(sw_header.trace_id().size()){
		req_co->uctx.ss_trace_id = strtoull(sw_header.trace_id().data(), NULL, 10);
		strncpy(req_co->uctx.ss_trace_id_s, sw_header.trace_id().data(), sizeof(req_co->uctx.ss_trace_id_s) - 1);
	}else{
		uint64_t ss_trace_id = (uid<<32)|time(NULL)|(random());
		req_co->uctx.ss_trace_id = ss_trace_id;
		snprintf(req_co->uctx.ss_trace_id_s, sizeof(req_co->uctx.ss_trace_id_s) - 1, "%" PRIu64, ss_trace_id);
	}

	if(swoole_ctx){
		util_parse_pb_from_json((blink::UserContext*)(req_co->proto_user_ctx), swoole_ctx);
	}

	
	((blink::UserContext*)(req_co->proto_user_ctx))->set_flag_test(sw_header.flag_test());
	if(sw_header.has_user_ip()){
		strncpy(req_co->uctx.cli_ip, sw_header.user_ip().data(), sizeof(req_co->uctx.cli_ip));
		((blink::UserContext*)(req_co->proto_user_ctx))->set_cli_ip(sw_header.user_ip());
	}else{
		req_co->uctx.cli_ip[0] = 0;
	}

	if(sw_header.has_platform() && sw_header.platform().size()){
		strncpy(req_co->uctx.platform, sw_header.platform().data(), sizeof(req_co->uctx.platform));
		((blink::UserContext*)(req_co->proto_user_ctx))->set_platform(sw_header.platform());
	}else{
		req_co->uctx.platform[0] = 0;
	}

	INIT_LIST_HEAD(&req_co->ptr_list);
	list_add(&req_co->ptr_list, &ptr->co_list);

	req_co->arg1 = ptr;
	req_co->arg2 = req_co;
	req_co->pre = worker->wt_co;
	req_co->ptr_closed = 0;

	//TODO set other parameter in uctx
	req_co->uctx.uid = uid;
	req_co->uctx.flag_test = sw_header.flag_test();
	req_co->ss_req_id = head->header_seq;
	req_co->sys_code = 0;

	memcpy(req_co->swoole_head, head, sizeof(swoole_head_t));
	//req_co->swoole_head = head;
	req_co->json_req_root = root;
	req_co->json_swoole_body_head = header;
	req_co->json_swoole_body_body = swoole_body;
	req_co->json_swoole_body_http = swoole_http;

	printf("resume json coroutine\n");
	co_resume(req_co);
	printf("json coroutine end\n");
	if(ptr->tmp){
		req_co->ptr_closed = 1;
	}
	co_release(&req_co);
	//json_object_put(root);
	return 0;
}

static int process_swoole_response(ev_ptr_t* ptr, swoole_head_t* head, char* body)
{
	uint64_t ss_req_id = head->header_seq;
	if(ss_req_id == 0){
		LOG_DBG("recv req id 0 response");
		return 0;
	}

	LOG_DBG("recv swoole response ss_req_id:%llu, service:%s", ss_req_id, head->cmd+1);
	coroutine_t* req_co = get_co_by_req_id(ptr, ss_req_id);
	if(NULL == req_co){
       if(ss_req_id != 1)
           LOG_ERR("no co for swoole response. worker:%llu ss_req_id %llu", (long long unsigned)ptr->arg, ss_req_id);
		return 0;
	}

	//std::string err_msg;
	int cost = 0;
	blink::UserContext user_ctx;
	json_object* js_body = json_tokener_parse(body);
	req_co->json_swoole_response = js_body;
	if(NULL != js_body){
		json_object* js_code = NULL;
		json_object_object_get_ex(js_body, "code", &js_code);
		req_co->sys_code = js_code?json_object_get_int(js_code):blink::EN_MSG_RET_PARSE_ERR;
		json_object* js_msg = NULL;
		json_object_object_get_ex(js_body, "msg", &js_msg);
		//js_msg&&json_object_to_json_string(js_msg)?(err_msg = json_object_to_json_string(js_msg), 0):0;
		req_co->err_msg[0] = 0;
		if(js_msg&&json_object_get_string(js_msg)){
			strncpy(req_co->err_msg, json_object_get_string(js_msg), sizeof(req_co->err_msg)-1);
		}
		//req_co->err_msg = err_msg.data();
		printf("//////////////////////swoole_ret_code:%d////////////////////\n", req_co->sys_code);
		if(!req_co->sys_code){
			json_object* js_data = NULL;
			json_object_object_get_ex(js_body, "data", &js_data);
			req_co->json_swoole_body_data = js_data;
		}

#if 0
		json_object* js_pb_svr = NULL;
		json_object_object_get_ex(js_body, "pb_svr", &js_pb_svr);
		if(js_pb_svr && req_co->proto_user_ctx){
			blink::UserContext ctx;
			if(!util_parse_pb_from_json(&ctx, js_pb_svr)){
				((blink::UserContext*)(req_co->proto_user_ctx))->CopyFrom(ctx);
			}
		}
#endif

		json_object* js_extra = NULL;
		json_object_object_get_ex(js_body, "extra", &js_extra);
		if(js_extra){
			json_object* js_cost = NULL;
			json_object_object_get_ex(js_extra, "cost", &js_cost);
            cost = js_cost?json_object_get_double(js_cost)*1000:0;
		}
	}else{
		req_co->sys_code = blink::EN_MSG_RET_PARSE_ERR;
	}

	if(req_co->sys_code < 0){
		fail_circuit_breaker(ptr->breaker);
	}else{
		succ_circuit_breaker(ptr->breaker);
	}

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	util_del_item(worker->co_cache, &(ss_req_id), sizeof(ss_req_id));

	if(is_co_in_batch_mode(req_co)){
		batch_rpc_result_t* rslt = get_co_req_rslt_by_req_id(req_co, ss_req_id);
		if(NULL == rslt){
			json_object_put(js_body);
			js_body = NULL;
			req_co->json_swoole_response = NULL;
			LOG_ERR("failed to get rslt of req:%llu", ss_req_id);
			return 0;
		}
		mc_collect(worker, &rslt->rpc_info, cost, req_co->sys_code, 1, req_co->uctx.ss_trace_id_s);
		init_user_context(&user_ctx, &rslt->rpc_info, cost, req_co->sys_code);
		append_trace_point(req_co, &rslt->rpc_info, &user_ctx, req_co->sys_code);

		rslt->finish = 1;
		rslt->sys_code = req_co->sys_code;
		if(rslt->rsp && !rslt->sys_code){
			if(util_parse_pb_from_json(rslt->rsp, (json_object*)(req_co->json_swoole_body_data))){
				LOG_ERR("failed to parse %s:%s response", rslt->rpc_info.service, rslt->rpc_info.method);
				rslt->sys_code = blink::EN_MSG_RET_PARSE_ERR;
			}
		}

		if(ptr == (ev_ptr_t*)(rslt->ptr)){
			--(ptr->num_async_out);
		}

		json_object_put(js_body);
		js_body = NULL;
		req_co->json_swoole_response = NULL;
		--req_co->batch_req_num;
		LOG_DBG("worker:%llu, traceid:%llu, request to %s:%d fd:%d ss_seq_id:%llu, finished. num async out:%d, remain batch_req_num:%d,service:%s,cost_time:%llums",  \
		(unsigned long long)worker,  req_co->uctx.ss_trace_id, ptr->ip, ptr->port, ptr->fd,ss_req_id, ptr->num_async_out, req_co->batch_req_num, rslt->rpc_info.service, get_milli_second()-rslt->ts);

		if(req_co->batch_req_num){
			return 0;
		}
	}else{
		mc_collect(worker, &req_co->rpc_info, cost, req_co->sys_code, 0, req_co->uctx.ss_trace_id_s);
		init_user_context(&user_ctx, &req_co->rpc_info, cost, req_co->sys_code);
		append_trace_point(req_co, &req_co->rpc_info, NULL, req_co->sys_code);
	}

	do_fin_request(req_co);
	del_timeout_event_from_timer(&(worker->timers), &(req_co->req_co_timeout_wheel));

	printf("////////////////////resume swoole co begin//////////////////\n");
	co_resume(req_co);
	printf("////////////////////resume swoole co end//////////////////\n");
	if(js_body){
		json_object_put(js_body);
		js_body = NULL;
		req_co->json_swoole_response = NULL;
	}
	co_release(&req_co);
	//TODO 
	return 0;
}

int process_swoole_request_from_ev_ptr(ev_ptr_t* ptr)
{
	swoole_head_t head;
	memset(&head, 0, sizeof(head));
	int rc = 0;
	std::vector<iovec> iovs;
	char sz_body[1024000];
	while(util_get_rd_buff_len(ptr->recv_chain) >= (int)sizeof(head)){
		iovs.clear();
		rc = util_get_rd_buff(ptr->recv_chain, sizeof(head), iovs);
		if(rc){
			return 0;
		}

		pad_mem_with_iovecs(iovs, (char*)&head, sizeof(head));
		swoole_head_ntohl(&head);
		LOG_DBG("magic:%u, ss_req_id:%u from:%s:%d", head.header_magic, head.header_seq, ptr->ip, ptr->port);
		if(head.header_magic != K_SWOOLE_MAGIC){
			LOG_ERR("invalid swoole magic:%u, from %s:%d", head.header_magic, ptr->ip, ptr->port);
			return -1;
		}

		if((unsigned)util_get_rd_buff_len(ptr->recv_chain) <(unsigned)(sizeof(head)+head.header_len )){
			return 0;
		}

		util_advance_rd(ptr->recv_chain, sizeof(head));
		if(0 == head.header_len){
			LOG_DBG("recv heartbeat from:%d", ptr->fd);
			continue;
		}

		if(head.header_len > sizeof(sz_body)-1){
			LOG_ERR("too big packet from:%d", ptr->fd);
			return -1;
		}

		sz_body[head.header_len] = 0;

		iovs.clear();
		util_get_rd_buff(ptr->recv_chain, head.header_len, iovs);
		pad_mem_with_iovecs(iovs, sz_body, head.header_len);
		util_advance_rd(ptr->recv_chain, head.header_len);

		char type = head.cmd[0];
		if(strncmp(head.cmd+1, "ping.ping", 9) == 0 && type == K_SWOOLE_RESPONSE){
			LOG_DBG("recv swoole ping response. type:%c", type);
			continue;
		}

		switch(type){
			case K_SWOOLE_REQUEST:
				rc = process_swoole_request(ptr, &head, sz_body);
				break;
			case K_SWOOLE_RESPONSE:
				rc = process_swoole_response(ptr, &head, sz_body);
				break;
			default:
				LOG_ERR("invalid swoole package type:%d", type);
				return -1;
		}

		if(rc){
			return -2;
		}
	}

	return 0;
}

void async_swoole_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr)
{
	coroutine_t co;
	memset(&co, 0, sizeof(coroutine_t));
	co.uctx.uid = 1;
	co.uctx.ss_trace_id_s[0] = '0';
	int rc = write_req_2_swoole_server(ptr, &co, 1, "ping", "ping.ping", NULL);
	if(rc){
		LOG_ERR("failed to write heartbeat package to swoole server");
		return;
	}

	LOG_DBG("send heart beat to swoole service. worker:%llu %s:%d fd:%d", (unsigned long long)worker, ptr->ip, ptr->port, ptr->fd);
	ptr->do_write_ev = do_write_msg_to_tcp;
	add_write_ev(worker->epoll_fd, ptr);
	do_write_msg_to_tcp(ptr);
}

int serialize_json_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg)
{
	json_object* js = json_object_new_object(); 
	if(NULL == js){
		LOG_ERR("failed to new js object");
		return -1;
	}

	json_object* body_code = json_object_new_int(ret_code);
	json_object_object_add(js, "code", body_code);

	json_object* body_msg = json_object_new_string(err_msg?err_msg:"");
	json_object_object_add(js, "msg", body_msg);

	if(!ret_code){
		int array = 0;
		json_object* body_data = util_parse_json_from_pb(msg, &array);
		if(body_data){
			if(!array){
				json_object* shit = json_object_new_int(0);
				json_object_object_add(body_data, "_gt_", shit);
			}
			json_object_object_add(js, "data", body_data);
		}
	}

	if(co->proto_user_ctx){
		json_object* pb_svr = util_parse_json_from_pb((blink::UserContext*)(co->proto_user_ctx));
		json_object_object_add(js, "pb_svr", pb_svr);
	}

	const char* str = json_object_to_json_string(js);
	size_t len = strlen(str);
	swoole_head_t* head = (swoole_head_t*)(co->swoole_head);
    //add by weisai
    char* cmd = head->cmd;
    *cmd = '1'; //response package flag
    while (*cmd != '\0')  cmd++; 
    *cmd = '.';
	head->header_len = (uint32_t)len;
	set_swoole_head_cmd(head, K_SWOOLE_RESPONSE, NULL);
	swoole_head_htonl(head);
	int rc = util_write_buff_data(ptr->send_chain, (char*)(co->swoole_head), sizeof(swoole_head_t));
	if(rc < 0){
		json_object_put(js);
		LOG_ERR("failed to write head");
		return -2;
	}

	util_write_buff_data(ptr->send_chain, str, len);
	json_object_put(js);
	return 0;
}

int async_req_with_swoole_msg(worker_thread_t* worker, coroutine_t* co, const char* service, const char* method, ::google::protobuf::Message* msg, int version, int timeout)
{
	ev_ptr_t* cli = get_cli_ptr(worker, co, service);
	if(NULL == cli){
		LOG_ERR("failed to client of service:%s", service);
		return blink::EN_MSG_RET_DEP_SERVICE_DOWN;
	}

	co->json_swoole_response = NULL;
	co->timeout = timeout;
	chg_co_timeout(co, cli);
	co->err_msg[0] = 0;
	int rc = prepare_co_before_async_call(co, cli);
	if(rc){
		return rc;
	}

	uint32_t ss_req_id = 0;
	if(co && co->wait_reply){
		ss_req_id = gen_32_id(worker);
	}

	LOG_DBG("call %s ss_req_id:%u\n", method, ss_req_id);
	rc = write_req_2_swoole_server(cli, co,  ss_req_id, service, method, msg, version, (blink::UserContext*)(co->proto_user_ctx));
	if(rc){
		LOG_ERR("failed to write request 2 swoole server");
		return rc;
	}

	if(co && co->wait_reply){
		LOG_DBG("set req. worker%llu ss_req_id:%llu, co:%llu", (long long unsigned)worker, ss_req_id, (long long unsigned)co);
		co->cache_req_id = ss_req_id;
		uint64_t req_id = ss_req_id;
		util_set_item(worker->co_cache, &req_id, sizeof(req_id), co, NULL);
		add_co_to_async_list(worker, co, cli);
	}

	cli->do_write_ev = do_write_msg_to_tcp;
	add_write_ev(worker->epoll_fd, cli);
	do_write_msg_to_tcp(cli);
	save_batch_co(co, cli, service, 0, ss_req_id);
	return 0;
}

static int write_req_2_swoole_server(ev_ptr_t* ptr, coroutine_t* co, uint32_t ss_req_id, const char* service, const char* method, ::google::protobuf::Message* msg, int version, blink::UserContext* uctx)
{
	json_object* js_swoole_body_header = (json_object*)(co->json_swoole_body_head);
	uint64_t uid = co->uctx.uid;
	const char* ss_trace_id_s = co->uctx.ss_trace_id_s;
	int flag_test = co->uctx.flag_test;

	swoole_head_t head;
	init_swoole_head(&head, (uint32_t)version);
	head.header_seq = ss_req_id;
	set_swoole_head_cmd(&head, K_SWOOLE_REQUEST, method);

	blink::SwooleBodyHeader header;
	header.set_platform("blink");
	header.set_src("src");
	header.set_version("0.0.0");
	header.set_buvid("blink");
	header.set_trace_id(ss_trace_id_s);
	header.set_uid(uid);
	header.set_caller(g_app_name?g_app_name:"unknow");
	header.set_flag_test(flag_test);
	header.set_need_trace(co->need_trace_point);
	if(uctx){
		header.set_user_ip(uctx->cli_ip());
		if(uctx->platform().size()){
			header.set_platform(uctx->platform());
		}
	}

	json_object* js = json_object_new_object();
	if(NULL == js){
		LOG_ERR("failed to create json object");
		return -1;
	}

	const char* bh = js_swoole_body_header?json_object_to_json_string(js_swoole_body_header):NULL; 
	json_object* body_header = bh?json_tokener_parse(bh):util_parse_json_from_pb(&header);
	json_object* body = (NULL == msg)? NULL:util_parse_json_from_pb(msg);
	//json_object* pb_svr = (NULL == uctx)?NULL:util_parse_json_from_pb(uctx);
	json_object_object_add(js, "header", body_header);
	if(body){
		json_object_object_add(js, "body", body);
	}

#if 0
	if(pb_svr){
		json_object_object_add(js, "pb_svr", pb_svr);
	}
#endif

	const char* str = json_object_to_json_string(js);
	int len = strlen(str);
	head.header_len = len;
	swoole_head_htonl(&head);

	util_write_buff_data(ptr->send_chain, (char*)&head, sizeof(head));
	util_write_buff_data(ptr->send_chain, str, len);
	printf("str:%s\n", str);
	json_object_put(js);

	return 0;
}
