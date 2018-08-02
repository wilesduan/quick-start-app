#ifndef __HTTP_GW_HANDLER_H__
#define __HTTP_GW_HANDLER_H__

#include <server.h>

typedef struct exe_info_t
{
	const char* app;
	const char* service;
	const char* method;

	uint64_t milli_start;
	uint64_t trace_id;
	uint64_t ss_req_id;
	int rc;
}exe_info_t;
int do_process_http_data(ev_ptr_t* ptr, coroutine_t* co);
#endif//__HTTP_GW_HANDLER_H__
