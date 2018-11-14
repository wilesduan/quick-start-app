#ifndef __LIB_SERVICE_monitor_monitor_data_PROTO_CLI_H__
#define __LIB_SERVICE_monitor_monitor_data_PROTO_CLI_H__

#include <blink.pb.h>
#include <gen_monitor_svr.pb.h>
#include <server.h>
#include <string>


int call_pb_monitor_monitor_data_add_monitor(rpc_ctx_t* ctx, blink::ReqAddMonitorLog* req);
int call_swoole_monitor_monitor_data_add_monitor(rpc_ctx_t* ctx, blink::ReqAddMonitorLog* req, int version=1);

#endif//__LIB_SERVICE_monitor_monitor_data_PROTO_CLI_H__
