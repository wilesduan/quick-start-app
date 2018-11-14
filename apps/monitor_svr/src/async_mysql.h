#ifndef __MONITOR_ASYNC_MYSQL_H__
#define __MONITOR_ASYNC_MYSQL_H__

#include <blink.pb.h>
#include <server.h>

int init_async_mysql_module(server_t* server);
int add_log_2_mysql(const blink::ReqAddMonitorLog* req);

#endif//__MONITOR_ASYNC_MYSQL_H__

