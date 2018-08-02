#ifndef __LIB_SERVICE_test_srv_echosrv_IMP_PROTO_H__
#define __LIB_SERVICE_test_srv_echosrv_IMP_PROTO_H__
#include <gen_echosrv.pb.h>
#include <server.h>


int do_test_srv_echosrv_echo(rpc_ctx_t* ctx, test_srv::echo_request* req, test_srv::echo_response* rsp);

#endif//__LIB_SERVICE_test_srv_echosrv_IMP_PROTO_H__
