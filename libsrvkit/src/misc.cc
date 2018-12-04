
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <server_inner.h>
#include <http2_client.h>

extern int g_log_trace_point;
extern char* g_app_name;

void log_trace_point(blink::UserContext* uctx);
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

static int get_lang(coroutine_t* co)
{
	if(!co)
		return 0;

	return ((co->uctx.dev_type)>>24);
}


int get_lang_by_rpc_ctx(rpc_ctx_t* ctx)
{
	return get_lang(ctx->co);
}

static const char* get_final_err_msg(coroutine_t* co, int ret_code, const char* err_msg)
{
	if(strlen(co->err_msg)){
		return co->err_msg;
	}

	worker_thread_t* worker = (worker_thread_t*)(co->worker);
	server_t* server = (server_t*)(worker->mt);
	if((!err_msg || !strlen(err_msg)) && server->fn_code_2_str){
		return (server->fn_code_2_str)(get_lang(co), ret_code);
	}

	return err_msg;
}

void ack_req_with_buff(ev_ptr_t* ptr, coroutine_t* co, int ret_code, const char* buf, size_t size, const char* err_msg)
{
	log_trace_point((blink::UserContext*)(co->proto_user_ctx));
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
	log_trace_point((blink::UserContext*)(co->proto_user_ctx));
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

static void moni_trace_point_cost(const char* service, const char* method, int milli_cost)
{
	std::string moni_key;
	moni_key.append("cost_").append(service).append("_").append(method);
	MONITOR_ACC(moni_key.data(), milli_cost);

	moni_key.clear();
	moni_key.append("cost_").append(service).append("_").append(method).append("_max");
	MONITOR_MAX(moni_key.data(), milli_cost);
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
	if(milli_cost){
		moni_trace_point_cost(service, method, milli_cost);
	}
}

void refill_trace_point(rpc_ctx_t* ctx, const char* service, const char* method, int milli_cost, int code)
{
	blink::UserContext* uctx = (blink::UserContext*)(ctx->co->proto_user_ctx);
	if(!uctx || !uctx->trace_points_size()){
		return;
	}

	blink::TracePoint* point = uctx->mutable_trace_points(0);
	point->set_milli_cost(milli_cost);
	point->set_err_code(code);
	if(milli_cost){
		moni_trace_point_cost(service, method, milli_cost);
	}
}

void append_trace_point(coroutine_t* co, rpc_info_t* info, const blink::UserContext* recv_ctx, int err_code)
{
	uint64_t now = get_milli_second();
	std::string moni_key;
	moni_key.append("qpm_").append(info->service).append("_").append(info->method);
	MONITOR_ACC(moni_key.data(), 1);
	moni_trace_point_cost(info->service, info->method, now-info->start_time);

	blink::UserContext* uctx = (blink::UserContext*)(co->proto_user_ctx);
	if(!uctx || !uctx->trace_points_size() || !recv_ctx || !recv_ctx->trace_points_size()){
		return;
	}


	blink::TracePoint* point = uctx->mutable_trace_points(0);
	blink::TracePoint* p = NULL;
	if(is_co_in_batch_mode(co)){
		int size = point->points_size();
		if(!size){
			return;
		}

		blink::TracePoint* batch_point = point->mutable_points(size-1);
		p = batch_point->add_points();
	}else{
		p = point->add_points();
	}

	p->CopyFrom(recv_ctx->trace_points(0));
	p->set_ip(info->ip);
	p->set_err_code(err_code);
	p->set_caller_rcv_ts(now);
	p->set_caller_cost(now-info->start_time);
	return;
}

void add_batch_trace_point(coroutine_t* co)
{
	blink::UserContext* uctx = (blink::UserContext*)(co->proto_user_ctx);
	if(!uctx || !uctx->trace_points_size()){
		return;
	}

	blink::TracePoint* point = uctx->mutable_trace_points(0);
	blink::TracePoint* p = point->add_points();
	p->set_service("callbatch");
	p->set_method("callbatch");
}

void fill_batch_trace_point_cost(coroutine_t* co)
{
	blink::UserContext* uctx = (blink::UserContext*)(co->proto_user_ctx);
	if(!uctx || !uctx->trace_points_size()){
		return;
	}

	blink::TracePoint* point = uctx->mutable_trace_points(0);
	int size = point->points_size();
	if(!size){
		return;
	}

	uint64_t now = get_milli_second();
	blink::TracePoint* p = point->mutable_points(size-1);
	p->set_milli_cost(now-co->rpc_info.start_time);
}

void log_trace_point(blink::UserContext* uctx)
{
	if(!g_log_trace_point || !uctx || !uctx->trace_points_size()){
		return;
	}

	const blink::TracePoint& point = uctx->trace_points(0);
	std::string str;
	util_pb2json(&point, str);
	LOG_INFO("#BLINK_NOTICE#[%s@log_trace|%s|%ums|%d|%llu|%d|%u][%s][]", g_app_name, uctx->ss_trace_id_s().data(), point.milli_cost(), point.err_code(), uctx->uid(), uctx->dev_type(), (unsigned)(uctx->dev_crc32()), str.data());
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

