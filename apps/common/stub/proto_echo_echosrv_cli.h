#ifndef __LIB_SERVICE_echo_echosrv_PROTO_CLI_H__
#define __LIB_SERVICE_echo_echosrv_PROTO_CLI_H__

#include <gen_echosrv.pb.h>
#include <server.h>
#include <string>


int call_pb_echo_echosrv_echo(rpc_ctx_t* ctx, echo::echo_request* req, echo::echo_response* rsp, int timeout=0);
int call_swoole_echo_echosrv_echo(rpc_ctx_t* ctx, echo::echo_request* req, echo::echo_response* rsp, int version=1, int timeout=0);

#endif//__LIB_SERVICE_echo_echosrv_PROTO_CLI_H__
