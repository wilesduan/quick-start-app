#ifndef __LIBSRVKIT_HTTP_H__
#define __LIBSRVKIT_HTTP_H__

#include <json.h>

typedef struct http_method_info_t
{
	unsigned int method : 8;       /* requests only */
	unsigned short http_major;
	unsigned short http_minor;
	const char* url;
	size_t url_len;
}http_method_info_t;

typedef struct http_extra_info_t
{
	const char* key;
	size_t key_len;
	const char* value;
	size_t value_len;
	list_head list;
}http_extra_info_t;

typedef struct http_body_t
{
	int app_json;
	const char* body;
	size_t body_len;
}http_body_t;

typedef struct http_request_t
{
	http_method_info_t method;
	list_head extra_info;
	http_body_t body;

	json_object* json_req_root;
	json_object* json_swoole_body_head;
	json_object* json_swoole_body_body;
	json_object* json_swoole_body_http;
}http_request_t;
#endif//__LIBSRVKIT_HTTP_H__

