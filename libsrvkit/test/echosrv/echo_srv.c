
#include <server.h>
#include <proto_test_srv_echosrv.h>

int main(int argc, char** argv)
{
	server_t* server = malloc_server(argc, argv);
	if(NULL == server){
		return 0;
	}

	service_t* service = gen_test_srv_echosrv_service();
	add_service(server, service);

	run_server(server);
	return 0;
}
