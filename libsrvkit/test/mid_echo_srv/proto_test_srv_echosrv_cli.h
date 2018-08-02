#ifndef __LIB_SERVICE_test_srv_echosrv_PROTO_CLI_H__
#define __LIB_SERVICE_test_srv_echosrv_PROTO_CLI_H__

#include <gen_echosrv.pb.h>
#include <server.h>
#include <string>


int call_pb_test_srv_echosrv_echo(rpc_ctx_t* ctx, test_srv::echo_request* req, test_srv::echo_response* rsp);
int call_swoole_test_srv_echosrv_echo(rpc_ctx_t* ctx, test_srv::echo_request* req, test_srv::echo_response* rsp, int version=1);

#endif//__LIB_SERVICE_test_srv_echosrv_PROTO_CLI_H__
