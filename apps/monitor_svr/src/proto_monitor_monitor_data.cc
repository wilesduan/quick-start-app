#include <proto_monitor_monitor_data.h>
#include <proto_monitor_monitor_data_imp.h>
#include <bim_util.h>
#include <gen_monitor_svr.pb.h>
#include <blink.pb.h>
#include <json.h>
#include <string>
#include <sys/time.h>
#include <swoole_def.h>

static int fn_pb_monitor_data_add_monitor(ev_ptr_t* ptr, coroutine_t* co)
{
	blink::ReqAddMonitorLog* req = new blink::ReqAddMonitorLog();
	rpc_ctx_t ctx;
	ctx.ptr= ptr;
	ctx.co = co;
	bool parse = req->ParseFromArray(co->params, co->size);
	if(!parse){
		LOG_ERR("[monitor_data][add_monitor]failed to parse request req, trace_id:%s uid:%llu", co->uctx.ss_trace_id_s, co->uctx.uid);
		delete req;
		return -1;
	}

	MONITOR_ACC("qpm_pb_add_monitor", 1);
	std::string req_str;
	util_pb2json(req, req_str);

	struct timeval start_tv, end_tv;
	gettimeofday(&start_tv,NULL);
	do_monitor_monitor_data_add_monitor(&ctx, req);
	gettimeofday(&end_tv,NULL);
	uint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;
	add_trace_point(&ctx, "monitor_data", "add_monitor", __FILE__, cost);
	LOG_INFO("#BLINK_NOTICE#[monitor_data@add_monitor|%s|%ums|0|%llu|%d|%u][%s]", co->uctx.ss_trace_id_s, cost, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), req_str.c_str());
	delete req;
	return 0;
}

static int fn_swoole_monitor_data_add_monitor(ev_ptr_t* ptr, coroutine_t* co)
{
	blink::ReqAddMonitorLog* req = new blink::ReqAddMonitorLog();
	rpc_ctx_t ctx;
	ctx.ptr= ptr;
	ctx.co = co;
	int rc = util_parse_pb_from_json(req, (json_object*)(co->json_swoole_body_body));
	if(rc){
		LOG_ERR("[monitor_data_ALARM][add_monitor]@failed to parse request req, trace_id:%s uid:%llu", co->uctx.ss_trace_id_s, co->uctx.uid);
		delete req;
		return -1;
	}

	MONITOR_ACC("qpm_swoole_add_monitor", 1);

	std::string req_str;
	util_pb2json(req, req_str);
	struct timeval start_tv, end_tv;
	gettimeofday(&start_tv,NULL);
	do_monitor_monitor_data_add_monitor(&ctx, req);
	gettimeofday(&end_tv,NULL);
	uint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;
	LOG_INFO("#BLINK_NOTICE#[monitor_data@add_monitor|%s|%ums|0|%llu|%d|%u][%s]", co->uctx.ss_trace_id_s, cost, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), req_str.c_str());
	add_trace_point(&ctx, "monitor_data", "add_monitor", __FILE__, cost);
	delete req;
	return 0;
}

service_t* gen_monitor_monitor_data_service()
{
	service_t* service = (service_t*)calloc(1, sizeof(service_t));
	if(NULL == service){
		LOG_ERR("[monitor_data_ALARM][monitor_data]@failed to alloc mem for service:monitor_data");
		return NULL;
	}

	INIT_LIST_HEAD(&service->list);
	service->name = strdup("monitor_data");
	service->num_methods= 1;
	service->methods = (fn_method*)calloc(2, sizeof(fn_method));
	service->swoole_meth = (swoole_method_t*)calloc(1, sizeof(swoole_method_t));
	service->methods[1] = fn_pb_monitor_data_add_monitor;

	service->swoole_meth[0].method = fn_swoole_monitor_data_add_monitor;
	service->swoole_meth[0].method_name = strdup("add_monitor");
	return service;
}
