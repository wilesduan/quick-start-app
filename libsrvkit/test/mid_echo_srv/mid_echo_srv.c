
#include <server.h>
#include <proto_mid_echo_srv_mid_echo_srv.h>

int main(int argc, char** argv)
{
	server_t* server = malloc_server(argc, argv);
	if(NULL == server){
		return 0;
	}

	service_t* service = gen_mid_echo_srv_mid_echo_srv_service();
	add_service(server, service);

	run_server(server);
	return 0;
}
