#include <proto_monitor_monitor_data_imp.h>
#include <async_mysql.h>

int do_monitor_monitor_data_add_monitor(rpc_ctx_t* ctx, blink::ReqAddMonitorLog* req)
{
	add_log_2_mysql(req);
	return 0;
}

