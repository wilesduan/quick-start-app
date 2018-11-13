#ifndef __LIBSRVKIT_HTTP2_CLIENT_H__
#define __LIBSRVKIT_HTTP2_CLIENT_H__
#include <server_inner.h>
#include <nghttp2/nghttp2.h>

typedef struct http2_payload_t
{
   void* data;
   ssize_t len;
}http2_payload_t;

int http2_ssl_connect(worker_thread_t* worker, proto_client_inst_t* cli, int fd);

int http2_submit_request(worker_thread_t* worker, const char* service, nghttp2_nv* nva, size_t sz, http2_payload_t* payload);
int async_http2_heartbeat(worker_thread_t* worker, ev_ptr_t* ptr);
int clean_http2_cli(worker_thread_t* worker, struct proto_client_inst_t* cli);
#endif//__LIBSRVKIT_HTTP2_CLIENT_H__

