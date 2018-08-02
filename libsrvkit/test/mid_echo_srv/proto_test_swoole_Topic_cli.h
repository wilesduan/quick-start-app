#ifndef __LIB_SERVICE_test_swoole_Topic_PROTO_CLI_H__
#define __LIB_SERVICE_test_swoole_Topic_PROTO_CLI_H__

#include <gen_swoole_test.pb.h>
#include <server.h>


int call_pb_test_swoole_Topic_send(rpc_ctx_t* ctx, test_swoole::req_publisher_topic* req, test_swoole::rsp_publisher_topic* rsp);
int call_swoole_test_swoole_Topic_send(rpc_ctx_t* ctx, test_swoole::req_publisher_topic* req, test_swoole::rsp_publisher_topic* rsp);

#endif//__LIB_SERVICE_test_swoole_Topic_PROTO_CLI_H__
