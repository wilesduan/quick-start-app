#ifndef __HTTP_INVOKE_H__
#define __HTTP_INVOKE_H__
#include <string>
#include <map>

enum HttpMethod
{
	UTIL_HTTP_GET = 1,
	UTIL_HTTP_POST = 2,
	UTIL_HTTP_HEAD = 3,
	UTIL_HTTP_OPTIONS = 4,
	UTIL_HTTP_PUT = 5,
	UTIL_HTTP_DELETE = 6,
	UTIL_HTTP_TRACE = 7,
	UTIL_HTTP_CONNECT = 8
};

int util_http_invoke(std::string url, int method, std::map<std::string, std::string>& key_vals, std::map<std::string, std::string>& files, 
                    std::string app_key, std::string app_secret, int& code, std::string& err_msg, std::string& content, bool is_retry = false, 
                    int connect_timeout = 5, int read_timeout = 50);

#endif//__HTTP_INVOKE_H__

