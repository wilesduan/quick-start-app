#include <proto_test_srv_echosrv_cli.h>
#include <bim_util.h>
#include <json.h>
#include <blink.pb.h>

int call_pb_test_srv_echosrv_echo(rpc_ctx_t* ctx, test_srv::echo_request* req, test_srv::echo_response* rsp)
{
	ctx->co->wait_reply = 1;
	char sz_mon_key[100];
	sz_mon_key[99] = 0;
	int rc = async_req_with_pb_msg((worker_thread_t*)ctx->co->worker, ctx->co, "echosrv", 1, req);
	if(rc){
		regist_rpc_info(&(ctx->co->rpc_info), "echosrv", "echo");
		mc_collect((worker_thread_t*)ctx->co->worker, &(ctx->co->rpc_info), 0, rc, 0, ctx->co->uctx.ss_trace_id_s);
		LOG_ERR("[echosrv_ALARM][echo]@call echosrv::echo failed. rc:%d, trace_id:%s, uid:%llu", rc, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		snprintf(sz_mon_key, 99, "async_req_%s_%s_errcode_%d", "echosrv", "echo", rc);
		MONITOR_ACC(sz_mon_key, 1);
		return rc;
	}

	if(is_co_in_batch_mode(ctx->co)){
		batch_rpc_result_t* last_rslt = get_co_last_req_rslt(ctx->co);
		last_rslt->rsp = rsp;
		regist_rpc_info(&(last_rslt->rpc_info), "echosrv", "echo");
		return 0;
	}

	regist_rpc_info(&(ctx->co->rpc_info), "echosrv", "echo");
	add_co_timeout_wheel((worker_thread_t*)(ctx->co->worker), ctx->co);
	BEGIN_CALC_RPC_COST();
	co_yield(ctx->co);
	END_CALC_RPC_COST("echosrv", "echo", ctx->co->uctx.ss_trace_id_s);

	if(ctx->co->sys_code){
		snprintf(sz_mon_key, 99, "call_%s_%s_errcode_%d", "echosrv", "echo", ctx->co->sys_code);
		MONITOR_ACC(sz_mon_key, 1);
		LOG_ERR("[echosrv_ALARM][echo]@return code:%d, trace_id:%s, uid:%llu", ctx->co->sys_code, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		return ctx->co->sys_code;
	}

	bool parse = rsp->ParseFromArray(ctx->co->params, ctx->co->size);
	if(!parse){
		snprintf(sz_mon_key, 99, "call_%s_%s_parse_err", "echosrv", "echo");
		MONITOR_ACC(sz_mon_key, 1);
		LOG_ERR("[echosrv][echo]failed to parse reponse of type:test_srv::echo_response, trace_id:%s", ctx->co->uctx.ss_trace_id_s);
		return blink::EN_MSG_RET_PARSE_ERR;
	}
	return 0;
}

int call_swoole_test_srv_echosrv_echo(rpc_ctx_t* ctx, test_srv::echo_request* req, test_srv::echo_response* rsp, int version)
{
	ctx->co->wait_reply = 1;
	char sz_mon_key[100];
	sz_mon_key[99] = 0;
	int rc = async_req_with_swoole_msg((worker_thread_t*)ctx->co->worker, ctx->co, "echosrv", "echosrv.echo", req, version);
	if(rc){
		regist_rpc_info(&(ctx->co->rpc_info), "echosrv", "echo");
		mc_collect((worker_thread_t*)ctx->co->worker, &(ctx->co->rpc_info), 0, rc, 0, ctx->co->uctx.ss_trace_id_s);
		snprintf(sz_mon_key, 99, "async_req_%s_%s_errcode_%d", "echosrv", "echo", rc);
		MONITOR_ACC(sz_mon_key, 1);
		LOG_ERR("[echosrv_ALARM][echo]@call echosrv::echo failed. rc:%d, trace_id:%s, uid:%llu", rc, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		return rc;
	}

	if(is_co_in_batch_mode(ctx->co)){
		batch_rpc_result_t* last_rslt = get_co_last_req_rslt(ctx->co);
		last_rslt->rsp = rsp;
		regist_rpc_info(&(last_rslt->rpc_info), "echosrv", "echo");
		return 0;
	}

	regist_rpc_info(&(ctx->co->rpc_info), "echosrv", "echo");
	add_co_timeout_wheel((worker_thread_t*)(ctx->co->worker), ctx->co);
	BEGIN_CALC_RPC_COST();
	co_yield(ctx->co);
	END_CALC_RPC_COST("echosrv", "echo", ctx->co->uctx.ss_trace_id_s);

	if(ctx->co->sys_code){
		LOG_ERR("[echosrv_ALARM][echo]@return code:%d, trace_id:%s, uid:%llu", ctx->co->sys_code, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		snprintf(sz_mon_key, 99, "call_%s_%s_errcode_%d", "echosrv", "echo", ctx->co->sys_code);
		MONITOR_ACC(sz_mon_key, 1);
		return ctx->co->sys_code;
	}

	rc = util_parse_pb_from_json(rsp, (json_object*)(ctx->co->json_swoole_body_data));
	if(rc){
		snprintf(sz_mon_key, 99, "call_%s_%s_parse_err", "echosrv", "echo");
		MONITOR_ACC(sz_mon_key, 1);
		LOG_ERR("[echosrv_ALARM][echo]@failed to parse reponse of type:test_srv::echo_response from json, trace_id:%s, uid:%llu", ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);
		return blink::EN_MSG_RET_PARSE_ERR;
	}
	return 0;
}

