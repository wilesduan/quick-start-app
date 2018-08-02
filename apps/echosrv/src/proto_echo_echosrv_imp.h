#ifndef __LIB_SERVICE_echo_echosrv_IMP_PROTO_H__
#define __LIB_SERVICE_echo_echosrv_IMP_PROTO_H__
#include <gen_echosrv.pb.h>
#include <server.h>


int do_echo_echosrv_echo(rpc_ctx_t* ctx, echo::echo_request* req, echo::echo_response* rsp);

#endif//__LIB_SERVICE_echo_echosrv_IMP_PROTO_H__
