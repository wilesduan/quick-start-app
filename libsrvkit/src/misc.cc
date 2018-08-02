
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <server_inner.h>
#include <http2_client.h>

void async_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr)
{
	if(ptr->process_handler == process_pb_request_from_ev_ptr){
		async_pb_heartbeat(worker, ptr);
	}else if(ptr->process_handler == process_swoole_request_from_ev_ptr){
		async_swoole_heartbeat(worker, ptr);
	}else if(ptr->process_handler == http2_ping_mark){
		async_http2_heartbeat(worker, ptr);
	}
}

static const char* get_final_err_msg(coroutine_t* co, int ret_code, const char* err_msg)
{
	if(strlen(co->err_msg)){
		return co->err_msg;
	}

	worker_thread_t* worker = (worker_thread_t*)(co->worker);
	server_t* server = (server_t*)(worker->mt);
	if((!err_msg || !strlen(err_msg)) && server->fn_code_2_str){
		return (server->fn_code_2_str)(ret_code);
	}

	return err_msg;
}

void ack_req_with_buff(ev_ptr_t* ptr, coroutine_t* co, int ret_code, const char* buf, size_t size, const char* err_msg)
{
	if(co->ptr_closed || 0 == ptr->fd){
		LOG_INFO("connection was closed before response");
		return;
	}
	//LOG_INFO("send buff size:%llu", size);

	err_msg = get_final_err_msg(co, ret_code, err_msg);

	if(ptr->process_handler == process_pb_request_from_ev_ptr){
		if(serialize_buff_to_send_chain(ptr, co, ret_code, buf, size, err_msg)){
            return;
        }

        ptr->do_write_ev = do_write_msg_to_tcp;
        worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
        add_write_ev(worker->epoll_fd, ptr);
		do_write_msg_to_tcp(ptr);
	}
}

void ack_req_with_rsp(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg)
{
	if(co->ptr_closed || 0 == ptr->fd){
		LOG_INFO("connection was closed before repsonse");
		return;
	}


	err_msg = get_final_err_msg(co, ret_code, err_msg);

	if(ptr->process_handler == process_pb_request_from_ev_ptr){
	   if(serialize_pb_to_send_chain(ptr, co, ret_code, msg, err_msg))
		   return;
	}else if(ptr->process_handler == process_swoole_request_from_ev_ptr){
		if(serialize_json_to_send_chain(ptr, co, ret_code, msg, err_msg)){
			return;
		}
	}else if(ptr->process_handler == process_http_request_from_ev_ptr){
		if(serialize_http_to_send_chain(ptr, co, ret_code, msg, err_msg)){
			return;
		}
	}else{
		LOG_ERR("unknow serialize type");
		return;
	}

	ptr->do_write_ev = do_write_msg_to_tcp;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	add_write_ev(worker->epoll_fd, ptr);
	do_write_msg_to_tcp(ptr);
}


void add_trace_point(rpc_ctx_t* ctx, const char* service, const char* method, const char* content, int milli_cost)
{
	if(!ctx || !ctx->co || !ctx->co->proto_user_ctx /*|| !ctx->co->need_trace_point*/){
		//LOG_ERR("invlaid parameter");
		return;
	}

	size_t sv_len = strlen(service);
	size_t mt_len = strlen(method);
	if(sv_len + mt_len > 90){
		return;
	}

	std::string moni_key;
	moni_key.append("qpm_").append(service).append("_").append(method);
	MONITOR_ACC(moni_key.data(), 1);

	moni_key.clear();
	moni_key.append("cost_").append(service).append("_").append(method);
	MONITOR_ACC(moni_key.data(), milli_cost);

	moni_key.clear();
	moni_key.append("cost_").append(service).append("_").append(method).append("_max");
	MONITOR_MAX(moni_key.data(), milli_cost);

	blink::UserContext* uctx = (blink::UserContext*)(ctx->co->proto_user_ctx);
	blink::TracePoint* point = uctx->add_trace_points();
	point->set_timestamp(get_milli_second());

	if(service)
		point->set_service(service);

	if(method)
		point->set_method(method);

	if(content)
		point->set_content(content);

	point->set_milli_cost(milli_cost);
}

void log_trace_point(blink::UserContext* uctx)
{
	if(!uctx){
		return;
	}

	std::string str;
	int rc = util_pb2json(uctx, str);
	if(rc){
		return;
	}

	LOG_INFO("%s", str.c_str());
}

void init_proto_uctx(blink::UserContext* proto_user_ctx)
{
	proto_user_ctx->set_uid(0);
	proto_user_ctx->set_cli_ip("xxx");
	proto_user_ctx->set_conn_ip("xxx");
	proto_user_ctx->set_conn_port(0);
}

char* read_file_content(const char* cfg)
{
	int fd = open(cfg, O_RDONLY);
	if(-1 == fd){
		LOG_DBG("failed to open file:%s\n", cfg);
		return NULL;
	}

	struct stat fst;
	if(stat(cfg, &fst) == -1){
		LOG_ERR("failed to stat file:%s\n", cfg);
		close(fd);
		return NULL;
	}

	char* fcontent = (char*)calloc(1, fst.st_size+1);
	if(NULL == fcontent){
		LOG_ERR("failed to calloc mem for file:%s\n", cfg);
		close(fd);
		return NULL;
	}

	if(read(fd, fcontent, fst.st_size) != fst.st_size){
		LOG_ERR("failed to read file:%s\n", cfg);
		close(fd);
		free(fcontent);
		return NULL;
	}

	close(fd);
	return fcontent;
}

void parse_zk_url(const char* url, char** host, char** path, char** added_group)
{
	if(NULL == url || (NULL == host && NULL == path && NULL == added_group)){
		return;
	}

	const char* p = url;
	while(*p != 0 && (*p == ' ' || *p == '\t' || *p == '\n')){
		++p;
	}

	if(*p == 0){
		return;
	}

	if(strncmp(p, "zk://", 5) != 0){
		return;
	}

	p += 5;
	const char* delim = p;
	while(*delim != 0 && *delim != '/'){
		++delim;
	}

	if(*delim == 0){
		return;
	}

	const char* param = delim+1;
	while(*param != 0 && *param != '?'){
		++param;
	}

	if(host)
		*host = strndup(p, delim-p);

	if(path)
		*path = strndup(delim, param-delim);

	if(added_group == NULL){
		return;
	}

	*added_group = NULL;
	if(*param == 0 || *(param+1) == 0){
		return;
	}

	const char* g = strstr(param+1, "added_group=");
	if(NULL == g){
		return;
	}

	p = g + 12;
	delim = p;
	while(*delim != 0 && *delim != '&'){
		++delim;
	}

	*added_group = strndup(p, delim - p);
}

