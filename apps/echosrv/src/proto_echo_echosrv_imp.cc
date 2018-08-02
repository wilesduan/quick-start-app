#include <proto_echo_echosrv_imp.h>


int do_echo_echosrv_echo(rpc_ctx_t* ctx, echo::echo_request* req, echo::echo_response* rsp)
{
	rsp->set_content(req->content());
	//TODO
	return 0;
}

