#include <proto_test_swoole_Topic_cli.h>
#include <bim_util.h>
#include <blink.pb.h>
#include <json.h>

int call_pb_test_swoole_Topic_send(rpc_ctx_t* ctx, test_swoole::req_publisher_topic* req, test_swoole::rsp_publisher_topic* rsp)
{
	/*
	int rc = async_req_with_pb_msg(ctx->ptr, ctx->co, "Topic", 1, req);
	if(rc){
		LOG_ERR("call Topic::send failed. rc:%d", rc);
		return rc;
	}

	add_co_timeout_wheel((worker_thread_t*)(ctx->ptr->arg), ctx->co);
	co_yield(ctx->co);

	if(ctx->co->sys_code){
		LOG_ERR("return code:%d", ctx->co->sys_code);
		return ctx->co->sys_code;
	}

	bool parse = rsp->ParseFromArray(ctx->co->params, ctx->co->size);
	if(!parse){
		LOG_ERR("failed to parse reponse of type:test_swoole::rsp_publisher_topic");
		return blink::EN_MSG_RET_PARSE_ERR;
	}
	*/
	return 0;
}

int call_swoole_test_swoole_Topic_send(rpc_ctx_t* ctx, test_swoole::req_publisher_topic* req, test_swoole::rsp_publisher_topic* rsp)
{
	/*
	int rc = async_req_with_swoole_msg(ctx->ptr, ctx->co, "Topic", "send", req);
	if(rc){
		LOG_ERR("call Topic::send failed. rc:%d", rc);
		return rc;
	}

	add_co_timeout_wheel((worker_thread_t*)(ctx->ptr->arg), ctx->co);
	co_yield(ctx->co);

	if(ctx->co->sys_code){
		printf("return code:%d\n", ctx->co->sys_code);
		LOG_ERR("return code:%d", ctx->co->sys_code);
		return ctx->co->sys_code;
	}

	rc = util_parse_pb_from_json(rsp, (json_object*)(ctx->co->json_swoole_body_data));
	if(rc){
		printf("failed to parse response\n");
		LOG_ERR("failed to parse reponse of type:test_swoole::rsp_publisher_topic from json");
		return blink::EN_MSG_RET_PARSE_ERR;
	}
	*/

	return 0;
}

