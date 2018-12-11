#ifndef __LIBSRVKIT_HTTP_CLIENT_H__
#define __LIBSRVKIT_HTTP_CLIENT_H__
#include <blink.pb.h>

#include <curl.h>
#include <multi.h>
#include <bim_util.h>
#include <server_inner.h>

struct rpc_ctx_t;

typedef struct http_info_t
{
	long  response_code;
	double total_cost;
	char local_ip[32];
	char remote_ip[32];
}http_info_t;

typedef struct http_request_t
{
	rpc_ctx_t* ctx;
	char error[CURL_ERROR_SIZE];
	blink::req_http* req;
	blink::rsp_http* rsp;
	http_info_t* info;

	curl_slist* headers;
	char* post_params;
	list_head list;
}http_request_t;


typedef struct http_client_t
{
	pthread_t pth;
	int epfd;//epollfd
	int tfd;     // timer filedescriptor
	int pipefd[2];//pipefd

	CURLM *multi;
	int still_running;

	pthread_mutex_t lock;
	list_head hrs;
	std::map<std::string, circuit_breaker_t*>* url_breakers;
}http_client_t;

typedef struct http_sock_info_t
{
	int sockfd;
	CURL *easy;
	int action;
	long timeout;
	http_client_t* hc;
}http_sock_info_t;

http_client_t* malloc_http_client();
void run_http_client(http_client_t* hc);
#endif//__LIBSRVKIT_HTTP_CLIENT_H__
