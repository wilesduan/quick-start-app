#include <server.h>
#include <http_gw_handler.h>

int main(int argc, char** argv)
{
	server_t* server = malloc_server(argc, argv);
	if(NULL == server){
		return 0;
	}

	mt_call_backs_t mt_fns;
	mt_fns.do_process_http_data = do_process_http_data;
	add_mt_call_backs(server, mt_fns);

	run_server(server);
	return 0;
}
