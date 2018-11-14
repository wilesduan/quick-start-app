#include <fstream>
#include <map>

#include "server.h"
#include "proto_monitor_monitor_data.h"
#include <async_mysql.h>

int fn_init(server_t* server){
	return init_async_mysql_module(server);
}


int main(int argc, char** argv)
{
	server_t* server = malloc_server(argc, argv);
	if(NULL == server){
		return 0;
	}
    
    //add udp data process call back
    mt_call_backs_t mt_fns;
    //bind prometheus listening port
    mt_fns.do_special_init = fn_init;
    add_mt_call_backs(server, mt_fns);

	service_t* service = gen_monitor_monitor_data_service();
	add_service(server, service);

	run_server(server);
	return 0;
}


