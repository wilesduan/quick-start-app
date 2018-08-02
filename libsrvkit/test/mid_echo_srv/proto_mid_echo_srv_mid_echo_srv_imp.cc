#include <proto_mid_echo_srv_mid_echo_srv_imp.h>
#include <proto_test_srv_echosrv_cli.h>
#include <proto_test_swoole_Topic_cli.h>


int do_mid_echo_srv_mid_echo_srv_echo(rpc_ctx_t* ctx, mid_echo_srv::mid_echo_request* req, mid_echo_srv::mid_echo_response* rsp)
{
#if 0
	printf("mid echo srv recv request:%s\n", req->content().c_str());
	rsp->set_content("hello");
	MONITOR_ACC("mid_echo_qps", 1);
	return 0;
#endif
#if 0

	std::string str_req;
	req->SerializeToString(&str_req);
	call_redis(ctx, "set test_binary %b", str_req.c_str(), str_req.size());
	redisReply* reply = call_redis(ctx, "get test_binary");

	mid_echo_srv::mid_echo_request rd_reply;
	rd_reply.ParseFromArray(reply->str, reply->len);
	printf("content from redis len:%llu:%d content:%s", str_req.size(), reply->len, rd_reply.content().c_str());
	rsp->set_content(rd_reply.content());
#endif

#if 0
	int n =0; 
	while(1){
		printf("hello:%d\n", ++n);
	char sz_key[100];
	begin_redis_pipeline(ctx);
	for(int i = 0; i < 100; ++i){
		sprintf(sz_key, "test_pipeline_%d", i);
		call_add_pipeline_command(ctx, "set %s %d", sz_key, i);
	}

	redisReply* reply = NULL;
	for(int i = 0; i < 100; ++i){
		reply = get_pipeline_reply(ctx);
	}
	end_redis_pipeline(ctx);

	begin_redis_pipeline(ctx);
	for(int i = 0; i < 100; ++i){
		sprintf(sz_key, "test_pipeline_%d", i);
		call_add_pipeline_command(ctx, "get %s", sz_key);
	}

	for(int i = 0; i < 100; ++i){
		sprintf(sz_key, "test_pipeline_%d", i);
		reply = get_pipeline_reply(ctx);
		printf("%s:%s\n", sz_key, reply->str);
	}
	end_redis_pipeline(ctx);
	sleep(1);
	}

	rsp->set_content(req->content());

	return 0;
#endif


	test_srv::echo_request* test_echo_req = new test_srv::echo_request();
	test_echo_req->set_content(req->content());
	test_srv::echo_response* test_echo_rsp = new test_srv::echo_response();
	int rc = call_pb_test_srv_echosrv_echo(ctx, test_echo_req, test_echo_rsp);
	//int rc = call_swoole_test_srv_echosrv_echo(ctx, test_echo_req, test_echo_rsp);
	printf("call service finish. rc:%d rsp:%s\n", rc, test_echo_rsp->content().c_str());
	if(rc){
		rsp->set_content("failed");
		goto free_mem;
	}

	rsp->set_content(test_echo_rsp->content());

free_mem:
	delete test_echo_req;
	delete test_echo_rsp;
	return 0;

	/*
	test_swoole::req_publisher_topic* req_topic = new test_swoole::req_publisher_topic();
	test_swoole::rsp_publisher_topic* rsp_topic = new test_swoole::rsp_publisher_topic();

	req_topic->set_topic("VCPlayNotify");
	req_topic->set_msg_id("1486719259207589d891b32a19");
	req_topic->set_msg_key("43004");
	test_swoole::req_content* content = req_topic->mutable_msg_content();
	content->set_video_id("43004");
	req_topic->set_timestamp(time(NULL));

	int rc = call_swoole_test_swoole_Topic_send(ctx, req_topic, rsp_topic);
	if(rc){
		printf("failed to call publisher\n");
		return -1;
	}

	printf("state:%d\n", rsp_topic->state());
	rsp->set_content("hello");
	*/
	return 0;
}

