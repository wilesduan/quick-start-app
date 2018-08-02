#include <http_gw_handler.h>
#include <string.h>

static void pre_process_http_request(rpc_ctx_t* ctx)
{
	json_object* header = (json_object*)(ctx->co->json_swoole_body_head);
	json_object* token = NULL;
	json_object_object_get_ex(header, "token", &token);
	if(!token){
		return;
	}

	json_object* js_app = NULL;
	json_object_object_get_ex(header, "app", &js_app);
	if(!js_app){
		return;
	}

	const char* app = json_object_get_string(js_app);

	json_object* config = ((server_t*) ((worker_thread_t*)(ctx->co->worker))->mt)->config;
	std::string app_key("appkey_");
	app_key.append(app);
	json_object* js_key = NULL;
	json_object_object_get_ex(config, app_key.data(), &js_key);
	if(!js_key){
		return;
	}

	const char* key = json_object_get_string(js_key);
	const char* str = json_object_get_string(token);
	size_t len = strlen(str);
	if(!len){
		return;
	}

	std::string base64(str);
	char* base64_decode = (char*)malloc(len);
	size_t base64_len = len;
	util_base64_decode(base64, base64_decode, &base64_len);

	size_t dec_len = len+16;
	char* dec_str = (char*)malloc(base64_len+16);
	int rc = util_aes_decrypt(key, base64_decode, base64_len, dec_str, &dec_len);
	if(!rc){
		free(base64_decode);
		free(dec_str);
		return;
	}

	/*
	   {"uid":xxxx, "expire":xxxxx}
	 */
	json_object* js_tk = json_tokener_parse(dec_str);
	free(base64_decode);
	free(dec_str);
	if(!js_tk){
		return;
	}

	json_object* js_uid = NULL;
	json_object* js_expire = NULL;
	json_object_object_get_ex(js_tk, "uid", &js_uid);
	json_object_object_get_ex(js_tk, "expire", &js_expire);
	if(!js_uid || !js_expire){
		json_object_put(js_tk);
		return;
	}

	uint64_t uid = json_object_get_int64(js_uid);
	uint64_t expire = json_object_get_int64(js_expire);
	json_object_put(js_tk);

	time_t now = time(NULL);
	if((uint64_t)(now) > 30 + expire){
		return;
	}

	ctx->co->uctx.uid = uid;
	js_uid = json_object_new_int64(uid);
	json_object_object_add(header, "uid", js_uid);
}

static int call_backend_swoole_service(rpc_ctx_t* ctx, exe_info_t* info)
{
	json_object* header = (json_object*)(ctx->co->json_swoole_body_head);
	const char* service = info->service;
	const char* method = info->method;
	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	//0. get cli_ptr
	ev_ptr_t* cli = get_cli_ptr(worker, ctx->co, service);
	if(NULL == cli){
		LOG_ERR("failed to get service:%s connection", service);
		return 404;
	}

	//1. gen trace id
	uint64_t trace_id = ((uint64_t)cli)|(random()<<32)|(time(NULL));
	json_object* js_trace = json_object_new_int64(trace_id);
	json_object_object_add(header, "trace_id", js_trace);
	info->trace_id = trace_id;

	//2. gen req id
	uint32_t ss_req_id = gen_32_id(worker);
	info->ss_req_id = ss_req_id;

	coroutine_t* co = ctx->co;
	co->wait_reply = 1;
	co->timeout = 800;
	chg_co_timeout(co, cli);
	co->err_msg[0] = 0;
	int rc = prepare_co_before_async_call(co, cli);
	if(rc){
		return 500;
	}

	char swoole_method[33];
	int mlen = snprintf(swoole_method, 32, "%s.%s", service, method);
	swoole_method[mlen] = 0;
	swoole_head_t head;
	init_swoole_head(&head, 1);
	head.header_seq = ss_req_id;
	set_swoole_head_cmd(&head, K_SWOOLE_REQUEST, swoole_method);
	const char* str = json_object_to_json_string((json_object*)(ctx->co->json_req_root));
	int len = strlen(str);
	head.header_len = len;
	swoole_head_htonl(&head);
	util_write_buff_data(cli->send_chain, (char*)&head, sizeof(head));
	util_write_buff_data(cli->send_chain, str, len);

	co->json_swoole_response = NULL;
	co->cache_req_id = ss_req_id;
	uint64_t req_id = ss_req_id;
	util_set_item(worker->co_cache, &req_id, sizeof(req_id), co, NULL);
	add_co_to_async_list(worker, co, cli);
	cli->do_write_ev = do_write_msg_to_tcp;
	add_write_ev(worker->epoll_fd, cli);
	do_write_msg_to_tcp(cli);

	add_co_timeout_wheel(worker, ctx->co);
	co_yield(ctx->co);

	return 0;
}

static int check_if_downgrade(rpc_ctx_t* ctx, exe_info_t* info)
{
	json_object* config = ((server_t*) ((worker_thread_t*)(ctx->co->worker))->mt)->config;
	json_object* js_downgrade = NULL;
	json_object_object_get_ex(config, "downgrade", &js_downgrade);
	if(!js_downgrade){
		return 0;
	}

	const char* app = info->app;
	const char* service = info->service;
	const char* method = info->method;
	if(!app || !service || !method){
		LOG_ERR("downgrade since miss app(%s), service(%s) or method(%s).", app?app:"NULL", service?service:"NULL", method?method:"method");
		return 1;
	}


	std::string path("/");
	path.append(app).append("/").append(service).append("/").append(method);
	json_object* item = NULL;
	json_object_object_get_ex(js_downgrade, path.data(), &item);
	if(!item){
		return 0;
	}

	int ratio = json_object_get_int(item);
	int rd = random()%100;
	if(rd <= ratio){
		return 1;
	}

	return 0;
}

static void log_access(rpc_ctx_t* ctx, exe_info_t* info)
{
	uint64_t milli_end = get_milli_second();
	LOG_INFO("#BLINK_NOTICE#[http_gw /%s/%s/%s]|%" PRIu64 "|%" PRIu64 "ms|%d|%" PRIu64 "[%s] [%s]", info->app, info->service, info->method, info->trace_id, milli_end-info->milli_start, ctx->co->sys_code, ctx->co->uctx.uid, ctx->co->json_req_root?json_object_to_json_string((json_object*)(ctx->co->json_req_root)):"NULL", ctx->co->json_swoole_response?json_object_to_json_string((json_object*)(ctx->co->json_swoole_response)):"NULL");

	char tmp[128];
	int len = snprintf(tmp, 127, "qpm_http_%s_%s_%s", info->app, info->service, info->method);
	tmp[len] = 0;
	MONITOR_ACC(tmp, 1);

	len = snprintf(tmp, 127, "const_http_%s_%s_%s", info->app, info->service, info->method);
	tmp[len] = 0;
	MONITOR_ACC(tmp, milli_end - info->milli_start);

	if(info->rc){
		len = snprintf(tmp, 127, "call_http_%s_%s_%s_%d", info->app, info->service, info->method, info->rc);
		tmp[len] = 0;
		MONITOR_ACC(tmp, 1);
	}
}

static void init_exe_info(rpc_ctx_t* ctx, exe_info_t* info)
{
	info->milli_start = get_milli_second(); 
	json_object* header = (json_object*)(ctx->co->json_swoole_body_head);
	json_object* js_app = NULL;
	json_object* js_service = NULL;
	json_object* js_method = NULL;
	json_object_object_get_ex(header, "app", &js_app);
	json_object_object_get_ex(header, "service", &js_service);
	json_object_object_get_ex(header, "method", &js_method);

	info->app = js_app?json_object_get_string(js_app):NULL;
	info->service = js_service?json_object_get_string(js_service):NULL;
	info->method = js_method?json_object_get_string(js_method):NULL;
}

int do_process_http_data(ev_ptr_t* ptr, coroutine_t* co)
{
	rpc_ctx_t ctx;
	ctx.ptr = ptr;
	ctx.co = co;

	exe_info_t info;
	bzero(&info, sizeof(info));
	init_exe_info(&ctx, &info);

	//0. check if downgrade
	bool downgrade = check_if_downgrade(&ctx, &info);
	if(downgrade){
		ack_http_repsone(ptr, 204, "No Content", "text/html", NULL);
		return 0;
	}

	//1. pre-process
	pre_process_http_request(&ctx);
	
	//2. call backend service
	int rc = call_backend_swoole_service(&ctx, &info);
	info.rc = rc;
	log_access(&ctx, &info);

	if(co->ptr_closed){
		LOG_ERR("client close connection before response back");
		return 0;
	}

	switch(rc){
		case 0:
			{
				json_object* js_response = (json_object*)(co->json_swoole_response);
				const char* rsp = js_response?json_object_to_json_string(js_response):NULL;
				ack_http_repsone(ptr, 200, "OK", "application/json", rsp);
			}
		case 404:
			ack_http_repsone(ptr, 404, "Not Found", "text/html", "<p>Page Not Found\n");
			break;
		case 500:
			ack_http_repsone(ptr, 500, "Internal Server Error", "text/html", "<p>Internal Server Error\n");
			break;
		default:
			//403 Forbidden
			ack_http_repsone(ptr, 403, "Forbidden", "text/html", "<p>Forbidden\n");
			break;

	}
	return 0;
}
