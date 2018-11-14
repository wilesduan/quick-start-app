#include <proto_monitor_monitor_data_cli.h>
#include <bim_util.h>
#include <json.h>
#include <blink.pb.h>

int call_pb_monitor_monitor_data_add_monitor(rpc_ctx_t* ctx, blink::ReqAddMonitorLog* req)
{
	ctx->co->wait_reply = 0;
	char sz_mon_key[100];
	sz_mon_key[99] = 0;
	int rc = async_req_with_pb_msg((worker_thread_t*)ctx->co->worker, ctx->co, "monitor_data", 1, req);
	if(rc){
		regist_rpc_info(&(ctx->co->rpc_info), "monitor_data", "add_monitor");
		mc_collect((worker_thread_t*)ctx->co->worker, &(ctx->co->rpc_info), 0, rc, 0, ctx->co->uctx.ss_trace_id_s);
		LOG_ERR("[monitor_data_ALARM][add_monitor]@call monitor_data::add_monitor failed. rc:%d, trace_id:%s, uid:%llu", rc, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		snprintf(sz_mon_key, 99, "async_req_%s_%s_errcode_%d", "monitor_data", "add_monitor", rc);
		MONITOR_ACC(sz_mon_key, 1);
		return rc;
	}

	return rc;
}

int call_swoole_monitor_monitor_data_add_monitor(rpc_ctx_t* ctx, blink::ReqAddMonitorLog* req, int version)
{
	ctx->co->wait_reply = 0;
	char sz_mon_key[100];
	sz_mon_key[99] = 0;
	int rc = async_req_with_swoole_msg((worker_thread_t*)ctx->co->worker, ctx->co, "monitor_data", "add_monitor", req, version);
	if(rc){
		regist_rpc_info(&(ctx->co->rpc_info), "monitor_data", "add_monitor");
		mc_collect((worker_thread_t*)ctx->co->worker, &(ctx->co->rpc_info), 0, rc, 0, ctx->co->uctx.ss_trace_id_s);
		snprintf(sz_mon_key, 99, "async_req_%s_%s_errcode_%d", "monitor_data", "add_monitor", rc);
		MONITOR_ACC(sz_mon_key, 1);
		LOG_ERR("[monitor_data_ALARM][add_monitor]@call monitor_data::add_monitor failed. rc:%d, trace_id:%s, uid:%llu", rc, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		return rc;
	}

	return rc;
}

