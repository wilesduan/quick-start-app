#include <util_http_invoke.h>

#include <bim_util.h>
#include <curl.h>
#include <sstream>

std::string int_2_string(int n)
{
	std::ostringstream stream;
	stream << n;
	return stream.str();
}

size_t write_data(void* buffer,size_t size,size_t nmemb,void *stream)
{
	 std::string *s = (std::string*)stream;
	 s->append((char*)buffer, size * nmemb);
	 return (size * nmemb);
}

std::string encode_map(CURL *curl, std::map<std::string, std::string>& params)
{
	std::string ret;
	if(params.size() == 0)
	{
		return ret;
	}

	std::map<std::string, std::string>::iterator iter = params.begin();
	while(true)
	{
		ret.append(iter->first);
		ret.append("=");
		char* encode = curl_easy_escape(curl, iter->second.c_str(), iter->second.size());
		if(encode){
			ret.append(encode);
			curl_free(encode);
		}else{
			ret.append(iter->second);
		}
		
		++iter;
		if(iter != params.end()){
			ret.append("&");
		}else{
			break;
		}
	}

	return ret;
}

std::string get_sign(CURL *curl, std::string app_secret, std::map<std::string, std::string>& params)
{
	std::string str = encode_map(curl, params);
	str.append(app_secret);

	unsigned char md5[MD5_DIGEST_LENGTH] = "";	
	md5_sum(str.c_str(), str.size(), md5);

	char sign[33] = "";
	transform_md5(md5, sign);

	return std::string((const char*)sign);
}

std::string get_params(CURL *curl, std::string& app_key, std::string& app_secret, std::map<std::string, std::string>& key_vals)
{
	// 为了拼接参数做md5 -> sign
	// 把接口所有POST参数拼接（sign参数除外），如appkey=xx&ts=xx，按参数名称排序，最后再拼接上密钥AppSecret，做md5加密。
	std::map<std::string, std::string> params;
	bool is_appkey = app_key == "" ? false : true;
	if (is_appkey)
		params.insert(std::pair<std::string, std::string>("appkey", app_key));

	std::map<std::string, std::string>::iterator iter;
	for(iter = key_vals.begin(); iter != key_vals.end(); ++iter)
		params.insert(std::pair<std::string, std::string>(iter->first, iter->second));

	if (is_appkey)
		params.insert(std::pair<std::string, std::string>("ts", int_2_string(time(NULL))));
	if (is_appkey)
		params.insert(std::pair<std::string, std::string>("sign", get_sign(curl, app_secret, params)));

	return encode_map(curl, params);
}

int util_http_invoke(std::string url, int method, std::map<std::string, std::string>& key_vals, std::map<std::string, std::string>& files, 
                    std::string app_key, std::string app_secret, int& code, std::string& err_msg, std::string& content, bool is_retry, 
                    int connect_timeout, int read_timeout)
{
    CURL *curl = NULL;
    CURLcode res = CURL_LAST;
    std::string buf;
	std::string params_str;
	struct curl_httppost* lastptr = NULL;
	struct curl_httppost* formpost = NULL;

    if (url.empty())
    {
		code = CURLE_URL_MALFORMAT;
		return code;
    }

	// init
    curl = curl_easy_init();
	if (!curl)
	{
		return 0;
	}

	params_str = get_params(curl, app_key, app_secret, key_vals);

	if (method == UTIL_HTTP_GET)
	{
		url.append("?");
		url.append(params_str);
	}

	LOG_DBG("[util_http_invoke] url: %s", url.c_str());

	curl_easy_setopt(curl,CURLOPT_URL, url.c_str()); //url地址
	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION, write_data); //对返回的数据进行操作的函数地址
	curl_easy_setopt(curl,CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl,CURLOPT_POST, method == UTIL_HTTP_POST); //设置问非0表示本次操作为post
	if (method == UTIL_HTTP_POST)
		curl_easy_setopt(curl,CURLOPT_POSTFIELDS, params_str.c_str()); //设置问非0表示本次操作为post
	curl_easy_setopt(curl,CURLOPT_HEADER, 0); //将响应头信息和相应体一起传给write_data
	curl_easy_setopt(curl,CURLOPT_NOSIGNAL, 1L); // 多线程屏蔽信号
	curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT_MS, connect_timeout);
	curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS, read_timeout);

	// upload file
	std::map<std::string, std::string>::iterator iter;
	for(iter = files.begin(); iter != files.end(); ++iter)
		curl_formadd(&formpost, &lastptr, CURLFORM_PTRNAME, iter->first.c_str(), CURLFORM_FILE, iter->second.c_str(), CURLFORM_END);
	if (files.size() > 0 )
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	// End upload file

	res = curl_easy_perform(curl);
	LOG_DBG("[util_http_invoke] buf: %s", buf.c_str());	

	if (is_retry)
	{
		int retry_count = 3;
		while ((res == CURLE_OPERATION_TIMEDOUT) && (--retry_count >= 0)) {
			res = curl_easy_perform(curl);
			LOG_INFO("[util_http_invoke] retry.count: %d, res: %d", retry_count, res);
		}
	}

    if (curl) curl_easy_cleanup(curl);
	if (res != CURLE_OK)
	{
		LOG_ERR("[util_http_invoke] error! res: %d, msg: %s", res, curl_easy_strerror(res));
		code = res;
		err_msg = curl_easy_strerror(res);
	}
	content = buf;
	return res;
}
