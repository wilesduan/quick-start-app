#include <proto_test_srv_echosrv.h>
#include <proto_test_srv_echosrv_imp.h>
#include <bim_util.h>
#include <gen_echosrv.pb.h>
#include <blink.pb.h>
#include <json.h>
#include <string>
#include <sys/time.h>
#include <swoole_def.h>

static int fn_pb_echosrv_echo(ev_ptr_t* ptr, coroutine_t* co)
{
	test_srv::echo_request* req = new test_srv::echo_request();
	test_srv::echo_response* rsp = new test_srv::echo_response();
	rpc_ctx_t ctx;
	ctx.ptr= ptr;
	ctx.co = co;
	bool parse = req->ParseFromArray(co->params, co->size);
	if(!parse){
		LOG_ERR("[echosrv][echo]failed to parse request req, trace_id:%s uid:%llu", co->uctx.ss_trace_id_s, co->uctx.uid);
		ack_req_with_rsp(ptr, co, blink::EN_MSG_RET_PARSE_ERR, rsp);
		delete rsp;
		delete req;
		return -1;
	}

	MONITOR_ACC("qpm_pb_echo", 1);
	std::string req_str, rsp_str;
	struct timeval start_tv, end_tv;
	util_pb2json(req, req_str);
	gettimeofday(&start_tv,NULL);
	int rc = do_test_srv_echosrv_echo(&ctx, req, rsp);
	gettimeofday(&end_tv,NULL);
	uint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;
	util_pb2json(rsp, rsp_str);
	LOG_INFO("#BLINK_NOTICE#[echosrv@echo|%s|%ums|%d|%llu|%d|%u][%s][%s]", co->uctx.ss_trace_id_s, cost, rc, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), req_str.c_str(), rsp_str.c_str());
	add_trace_point(&ctx, "echosrv", "echo", __FILE__, cost);
	ack_req_with_rsp(ptr, co, rc, rsp);
	delete rsp;
	delete req;
	return 0;
}

static int fn_swoole_echosrv_echo(ev_ptr_t* ptr, coroutine_t* co)
{
	test_srv::echo_request* req = new test_srv::echo_request();
	test_srv::echo_response* rsp = new test_srv::echo_response();
	rpc_ctx_t ctx;
	ctx.ptr= ptr;
	ctx.co = co;
	int rc = util_parse_pb_from_json(req, (json_object*)(co->json_swoole_body_body));
	if(rc){
		LOG_ERR("[echosrv_ALARM][echo]@failed to parse request req, trace_id:%s uid:%llu", co->uctx.ss_trace_id_s, co->uctx.uid);
		ack_req_with_rsp(ptr, co, blink::EN_MSG_RET_PARSE_ERR, rsp);
		delete rsp;
		delete req;
		return -1;
	}

	MONITOR_ACC("qpm_swoole_echo", 1);
	std::string req_str, rsp_str;
	struct timeval start_tv, end_tv;
	util_pb2json(req, req_str);
	gettimeofday(&start_tv,NULL);
	rc = do_test_srv_echosrv_echo(&ctx, req, rsp);
	gettimeofday(&end_tv,NULL);
	uint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;
	util_pb2json(rsp, rsp_str);
	LOG_INFO("#BLINK_NOTICE#[echosrv@echo|%s|%ums|%d|%llu|%d|%u][%s][%s]", co->uctx.ss_trace_id_s, cost, rc, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), req_str.c_str(), rsp_str.c_str());
	add_trace_point(&ctx, "echosrv", "echo", __FILE__, cost);
	ack_req_with_rsp(ptr, co, rc, rsp);
	delete rsp;
	delete req;
	return 0;
}

service_t* gen_test_srv_echosrv_service()
{
	service_t* service = (service_t*)calloc(1, sizeof(service_t));
	if(NULL == service){
		LOG_ERR("[echosrv_ALARM][echosrv]@failed to alloc mem for service:echosrv");
		return NULL;
	}

	INIT_LIST_HEAD(&service->list);
	service->name = strdup("echosrv");
	service->num_methods= 1;
	service->methods = (fn_method*)calloc(2, sizeof(fn_method));
	service->swoole_meth = (swoole_method_t*)calloc(1, sizeof(swoole_method_t));
	service->methods[1] = fn_pb_echosrv_echo;

	service->swoole_meth[0].method = fn_swoole_echosrv_echo;
	service->swoole_meth[0].method_name = strdup("echo");
	return service;
}
