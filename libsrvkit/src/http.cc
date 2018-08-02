
#include <server_inner.h>
#include <vector>
#include <stdlib.h>
#include <http_parser.h>
#include <http.h>

extern char* g_app_name;

static json_object* get_swoole_body_http(http_request_t* req)
{
	if(req->json_swoole_body_http){
		return req->json_swoole_body_http;
	}

	json_object* http = json_object_new_object();
	req->json_swoole_body_http = http;
	json_object_object_add(req->json_req_root, "http", http);
	return http;
}

static json_object* get_swoole_body_head(http_request_t* req)
{
	if(req->json_swoole_body_head){
		return req->json_swoole_body_head;
	}

	json_object* head= json_object_new_object();
	req->json_swoole_body_head = head;
	json_object_object_add(req->json_req_root, "header", head);
	return head;
}

static json_object* get_swoole_body_body(http_request_t* req)
{
	if(req->json_swoole_body_body){
		return req->json_swoole_body_body;
	}

	json_object* body = json_object_new_object();
	req->json_swoole_body_body = body;
	//add in final
	//json_object_object_add(req->json_req_root, "body", body);
	return body;
}

static json_object* get_json_obj_from_json(json_object* jsn, const char* key)
{
	json_object* obj = NULL;
	json_object_object_get_ex(jsn, key, &obj);
	if(obj){
		return obj;
	}

	obj = json_object_new_object();
	json_object_object_add(jsn, key, obj);
	return obj;
}

static int get_expect_http_req_len(std::vector<iovec>& iovs)
{
	int state = 100;
	int content_length = 0;
	//int body_len = 0;
	int loop_end = 0;
	int parse_len = 0;
	for(size_t i = 0; i < iovs.size(); ++i){
		for(size_t k = 0; k < iovs[i].iov_len; ++k){
			char* p = (char*)(iovs[i].iov_base)+ k;
			++parse_len;
			switch(state){
				case 100:
				{
					if(*p == '\r'){
						state = 101;
					}
					break;
				}
				case 101:
				{
					state = 100;
					if(*p == '\n'){
						state = 200;
					}
					break;
				}
#define HTTP_PART2_ROLL_BACK state = 250; --k; --parse_len;
				//Content-Length:
				case 200:
				{
					if(*p == 'C' || *p == 'c'){
						state = 201;
						break;
					}

					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 201:
				{
					if(*p == 'o' || *p == 'O'){
						state = 202;
						break;
					}

					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 202:
				{
					if(*p == 'n' || *p == 'N'){
						state = 203;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 203:
				{
					if(*p == 't' || *p == 'T'){
						state = 204;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 204:
				{
					if(*p == 'e' || *p == 'E'){
						state = 205;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 205:
				{
					if(*p == 'n' || *p == 'N'){
						state = 206;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 206:
				{
					if(*p == 't' || *p == 'T'){
						state = 207;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				//Content-Length:
				case 207:
				{
					if(*p == '-'){
						state = 208;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 208:
				{
					if(*p == 'L' || *p == 'l'){
						state = 209;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 209:
				{
					if(*p == 'e' || *p == 'E'){
						state = 210;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 210:
				{
					if(*p == 'n' || *p == 'N'){
						state = 211;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 211:
				{
					if(*p == 'g' || *p == 'G'){
						state = 212;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 212:
				{
					if(*p == 't' || *p == 'T'){
						state = 213;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 213:
				{
					if(*p == 'h' || 'H'){
						state = 214;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 214:
				{
					if(*p == ':' ){
						state = 215;
						break;
					}
					HTTP_PART2_ROLL_BACK;
					break;
				}
				case 215:
				{
					if(isdigit(*p)){
						if(content_length){
							return 520;
						}

						content_length = (*p - '0');
						state = 216;
					}else if(*p != ' '){
						return 521;
					}
					break;
				}
				case 216:
				{
					if(isdigit(*p)){
						content_length = content_length*10 + (*p - '0');
					}else if(*p == '\r'){
						state = 217;
					}else{
						return 523;
					}
					break;
				}
				case 217:
				{
					if(*p == '\n'){
						state = 252;
					}else{
						return 524;
					}
					break;
				}
				case 250:
				{
					if(*p == '\r'){
						state = 251;
					}
					break;
				}
				case 251:
				{
					if(*p == '\n'){
						state = 252;
					}else{
						return 525;
					}
					break;
				}
				case 252:
				{
					if(*p == '\r'){
						state = 253;
					}else if(*p == 'C' || *p == 'c'){
						state = 201;
					}else{
						state = 250;
					}
					break;
				}
				case 253:
				{
					if(*p == '\n'){
						loop_end = 1;
						/*
						if(content_length){
							state = 300;
						}else{
							loop_end = 1;
						}
						*/
					}else{
						return 526;
					}
					break;
				}
				/*
				case 300:
				{
					++body_len;
					if(body_len >= content_length){
						loop_end = 1;
						break;
					}
					break;
				}
				*/
				default:
				    break;
			}

			if(loop_end){
				break;
			}
		}

		if(loop_end){
			break;
		}
	}

	printf("parse len:%d, content_length:%d\n", parse_len, content_length);
	if(!loop_end){
		return 0;
	}

	return parse_len+content_length;
}

static int on_message_begin(http_parser* parser) 
{
	printf("\n***MESSAGE BEGIN***\n\n");
	return 0;
}

static int on_headers_complete(http_parser* parser) 
{
	printf("\n***HEADERS COMPLETE***\n\n");
	return 0;
}

static int on_message_complete(http_parser* parser) 
{
	printf("\n***MESSAGE COMPLETE***\n\n");
	return 0;
}

static void add_kv_2_header(http_request_t* req, const char* key, size_t key_len, const char* val, size_t val_len)
{
	if(strncmp(key, "platform", key_len) && 
	   strncmp(key, "src", key_len)      && 
	   //strncmp(key, "uid", key_len)      && 
	   strncmp(key, "version", key_len)      && 
	   strncmp(key, "buvid", key_len>5?5:key_len)      
	  ){
		return;
	}

	json_object* header = get_swoole_body_head(req);
	if(!header){
		return;
	}

	std::string k(key, key_len);
	json_object* obj = json_object_new_string_len(val, val_len);
	json_object_object_add(header, k.data(), obj);
	return;
}

static void add_kv_2_body(http_request_t* req, const char* key, size_t key_len, const char* val, size_t val_len)
{
	json_object* body = get_swoole_body_body(req);
	if(!body){
		LOG_ERR("failed to get swoole body body");
		return;
	}

	if(key_len > 2 && key[key_len-2] == '[' && key[key_len-1] == ']'){
		std::string k(key, key_len-2);
		json_object* array = NULL;
		json_object_object_get_ex(body, k.data(), &array);
		if(!array){
			array = json_object_new_array();
			json_object_object_add(body, k.data(), array);
		}

		json_object* item = json_object_new_string_len(val, val_len);
		json_object_array_add(array, item);
		return;
	}

	std::string k(key, key_len);
	json_object* obj = NULL;
	json_object_object_get_ex(body, k.data(), &obj);
	if(obj){
		LOG_ERR("key:%.*s already exist", (int)key_len, key);
		return;
	}

	obj = json_object_new_string_len(val, val_len);
	json_object_object_add(body, k.data(), obj);
}

static void add_url_params(http_request_t* req, const char* key, size_t key_len, const char* val, size_t val_len)
{
	if(!(key && *key && key_len && val && *val && val_len)){
		LOG_ERR("invalid key value");
		return;
	}

	add_kv_2_header(req, key, key_len, val, val_len);
	add_kv_2_body(req, key, key_len, val, val_len);
}

static int on_url(http_parser* parser, const char* at, size_t length) 
{
	http_request_t* req = (http_request_t*)(parser->data);
	req->method.url = at;
	req->method.url_len = length;

	printf("Url: %.*s\n", (int)length, at);

	/********add url to http**********/
	json_object* http = get_swoole_body_http(req);
	if(!http){
		LOG_ERR("failed to get http from req");
		return 501;
	}

	json_object* url = json_object_new_string_len(at, length);
	json_object_object_add(http, "uri_with_params", url);
	/********end add url to http**********/

	/********parse url**********/
	const char* params = at+length;
	const char* p = at;
	while(p < at+length && *p != '?') ++p;
	if(p && *p == '?'){
		params = p++;
	}

	const char* key = p;
	size_t key_len = 0;
	const char* val = NULL;
	size_t val_len = 0;
	int state = 1;
	while(p < at+length && *p != '#'){
		switch(state){
			case 1:
				{
					if(*p == '='){
						key_len = p - key;
						state = 2;
						val = p+1;
					}
					break;
				}
			case 2:
				{
					if(*p == '&'){
						val_len = p - val;
						add_url_params(req, key, key_len, val, val_len);
						state = 1;
						key = p+1;
					}
					break;
				}
			default:
				{
					break;
				}
		}
		++p;
	}

	if(p){
		val_len = p - val;
		add_url_params(req, key, key_len, val, val_len);
	}
	/********end parse url**********/
	//add uri to http
	json_object* uri = json_object_new_string_len(at, params - at);
	json_object_object_add(http, "uri", uri);

	return 0;
}

static int on_header_field(http_parser* parser, const char* at, size_t length) 
{
	http_extra_info_t* extra = (http_extra_info_t*)calloc(1, sizeof(http_extra_info_t));
	INIT_LIST_HEAD(&extra->list);
	extra->key = at;
	extra->key_len = length;

	http_request_t* req = (http_request_t*)(parser->data);
	list_add_tail(&extra->list, &(req->extra_info));

	printf("Header field: %.*s\n", (int)length, at);
	return 0;
}

static int on_header_value(http_parser* parser, const char* at, size_t length) {
	http_request_t* req = (http_request_t*)(parser->data);
	if(list_empty(&req->extra_info)){
		LOG_ERR("invalid header value");
		return -1;
	}

	list_head* p = req->extra_info.prev;
	http_extra_info_t* extra = list_entry(p, http_extra_info_t, list);
	extra->value = at;
	extra->value_len = length;
	
	if(strncasecmp(extra->key, "Content-Type:", extra->key_len>13?13:extra->key_len) == 0&& strncasecmp(extra->value, "application/json", length>16?16:length) == 0){
		req->body.app_json = 1;
	}

	printf("Header value: %.*s\n", (int)length, at);
	add_kv_2_header(req, extra->key, extra->key_len, extra->value, extra->value_len);

	json_object* http = get_swoole_body_http(req);
	json_object* header = get_json_obj_from_json(http, "header");
	if(!header){
		return -2;
	}

	std::string key(extra->key, extra->key_len);
	json_object* obj = NULL;
	json_object_object_get_ex(header, key.data(), &obj);
	if(obj){
		return 0;
	}

	obj = json_object_new_string_len(extra->value, extra->value_len);
	json_object_object_add(header, key.data(), obj);
	return 0;
}

static int on_body(http_parser* parser, const char* at, size_t length) {
	http_request_t* req = (http_request_t*)(parser->data);
	req->body.body = at;
	req->body.body_len = length;
	printf("Body: %.*s\n", (int)length, at);

	return 0;
}

static void init_http_request(http_request_t* request)
{
	memset(&(request->method), 0, sizeof(http_method_info_t));
	INIT_LIST_HEAD(&request->extra_info);
	memset(&(request->body), 0, sizeof(http_body_t));
	request->json_req_root = json_object_new_object();
	request->json_swoole_body_head = request->json_swoole_body_body = request->json_swoole_body_http = NULL;
}

static void free_http_request_extra_info(http_request_t* request)
{
	list_head* p = NULL;
	list_head* next = NULL;
	list_for_each_safe(p, next, &request->extra_info){
		http_extra_info_t* extra = list_entry(p, http_extra_info_t, list);
		list_del(p);
		free(extra);
	}
}

static void parse_url_path(http_request_t* request)
{
	json_object* js[3] = {NULL};

	int i = 0;
	const char* poilt = NULL;
	const char* p = request->method.url;

	json_object* header = get_swoole_body_head(request);

loop:
	while(p < p+request->method.url_len){
		if(*p != '/'){
			poilt = p;
			break;
		}
		++p;
	}

	while(p < p+request->method.url_len){
		if(*p == '/' || *p == '?' || *p == '#' || *p == ' '){
			js[i++] = json_object_new_string_len(poilt, p - poilt);
			poilt = NULL;
			break;
		}
		++p;
	}

	if(i < 3 && p < p+request->method.url_len){
		goto loop;
	}

	if(i < 3 && poilt && p-poilt){
		js[i++] = json_object_new_string_len(poilt, p - poilt);
	}

	if(i < 3){
		if(js[0]) json_object_put(js[0]);
		if(js[1]) json_object_put(js[1]);
		return;
	}

	json_object_object_add(header, "app", js[0]);
	json_object_object_add(header, "service", js[1]);
	json_object_object_add(header, "method", js[2]);
	return;
}

static int do_process_http_request(ev_ptr_t* ptr, http_request_t* request)
{
	printf("root:%s\n", json_object_to_json_string(request->json_req_root));
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	server_t* server = (server_t*)(worker->mt);

	json_object* header = get_swoole_body_head(request);
	json_object* js_app = NULL;
	json_object* js_service = NULL;
	json_object* js_method = NULL;
	json_object_object_get_ex(header, "app", &js_app);
	json_object_object_get_ex(header, "service", &js_service);
	json_object_object_get_ex(header, "method", &js_method);

	if(!js_app || !js_service || !js_method){
		LOG_ERR("invalid request url:%*.s", request->method.url_len, request->method.url);
		return 404;
	}

	//const char* app = json_object_get_string(js_app);
	const char* service = json_object_get_string(js_service);
	const char* method = json_object_get_string(js_method);

	fn_method fn = get_swoole_fn_method(worker, service, method);
	fn = (!fn)?server->mt_fns.do_process_http_data:fn;
	if(NULL == fn){
		LOG_ERR("no handler for %s/%s", service, method);
		return 404;
	}


	swoole_head_t swl_hd;
	return do_process_swoole_request(worker, ptr, &swl_hd, fn, request->json_req_root, header, get_swoole_body_body(request), get_swoole_body_http(request), NULL);
}

static void final_parse_body(http_request_t* request)
{
	json_object* body = NULL;
	if(!request->body.app_json || !(request->body.body) || !(body = json_tokener_parse(request->body.body))){
		if(request->json_swoole_body_body){
			json_object_object_add(request->json_req_root, "body", request->json_swoole_body_body);
		}
		return;
	}

	json_object_object_add(request->json_req_root, "body", body);

	if(!request->json_swoole_body_body){
		request->json_swoole_body_body = body;
		return;
	}

	lh_table* table = json_object_get_object(request->json_swoole_body_body);
	if(!table){
		json_object_put(request->json_swoole_body_body);
		return;
	}

	lh_entry* entry = table->head;
	while(entry){
		const char* k = (char*)entry->k;
		json_object* v = (json_object*)entry->v;

		json_object* obj = NULL;
		json_object_object_get_ex(body, k, &obj);
		if(!obj){
			obj = json_object_new_string(json_object_get_string(v));
			json_object_object_add(body, k, obj);
		}

		entry = entry->next;
	}

	json_object_put(request->json_swoole_body_body);
	request->json_swoole_body_body = body;
}

static void final_parse_http_req(http_request_t* request)
{
	final_parse_body(request);

	json_object* http =  get_swoole_body_http(request);
	json_object* method = NULL;
	switch(request->method.method){
		case 1:
			method = json_object_new_string("GET");
			break;
		case 3:
			method = json_object_new_string("POST");
			break;
		default:
			LOG_ERR("unsupport http method:%d", request->method.method);
			break;
	}
	if(method){
		json_object_object_add(http, "method", method);
	}

	char tmp[32];
	snprintf(tmp, 32, "HTTP/%d.%d", request->method.http_major, request->method.http_minor);
	json_object* protocol = json_object_new_string(tmp);
	json_object_object_add(http, "protocol", protocol);

	/**Get /app/service/method **/
	parse_url_path(request);
}

static int add_http_response_code(ev_ptr_t* ptr, int http_code, const char* desc)
{
	char tmp[1024];
	int len = snprintf(tmp, 1023, "HTTP/1.1 %d %s\r\n", http_code, desc);
	tmp[len] = 0;
	util_write_buff_data(ptr->send_chain, tmp, len);
	return 0;
}

static int add_http_response_header(ev_ptr_t* ptr, const char* k, const char* v)
{
	char tmp[1024];
	int len = snprintf(tmp, 1023, "%s: %s\r\n", k, v);
	tmp[len] = 0;
	util_write_buff_data(ptr->send_chain, tmp, len);
	return 0;
}

static int add_http_response_content(ev_ptr_t* ptr, const char* content)
{
	util_write_buff_data(ptr->send_chain, "\r\n", 2);
	util_write_buff_data(ptr->send_chain, content, strlen(content));
	return 0;
}

static int flush_http_response(ev_ptr_t* ptr)
{
	ptr->do_write_ev = do_write_msg_to_tcp;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	add_write_ev(worker->epoll_fd, ptr);
	do_write_msg_to_tcp(ptr);
	return 0;
}

int ack_http_repsone(ev_ptr_t* ptr, int http_code, const char* code_desc, const char* content_type, const char* content)
{
	add_http_response_code(ptr, http_code, code_desc);
	add_http_response_header(ptr, "Content-type", content_type);
	char tmp[64];
	snprintf(tmp, 64, "%" PRIu64, content?strlen(content):0);
	add_http_response_header(ptr, "Content-Length", tmp);
	//time_t now = time(NULL);
	//add_http_response_header(ptr, "Date", ctime(&now));
	content?add_http_response_content(ptr, content):0;

	flush_http_response(ptr);
	return 0;
}

int process_http_request_from_ev_ptr(ev_ptr_t* ptr)
{
	std::vector<iovec> iovs;
	int len = 0;util_get_rd_buff_len(ptr->recv_chain);
	while((len = util_get_rd_buff_len(ptr->recv_chain)) > 0)
	{
		iovs.clear();
		int rc = util_get_rd_buff(ptr->recv_chain, len, iovs);
		if(rc){
			LOG_ERR("failed to read bytes from iovs");
			return 0;
		}

		int expect_len = get_expect_http_req_len(iovs);
		printf("expect len:%d:%d\n", expect_len, len);
		if(expect_len<0){
			LOG_ERR("malformed http request");
			ack_http_repsone(ptr, 400, "Bad Request", "text/html", "<p>malformed http request\n");
			return -1;
		}else if(!expect_len || expect_len > len){
			return 0;
		}

		char* buff = (char*)malloc(expect_len+1);
		pad_mem_with_iovecs(iovs, buff, expect_len);
		buff[expect_len] = 0;

		util_advance_rd(ptr->recv_chain, expect_len);
		http_parser *parser = (http_parser*)calloc(1, sizeof(http_parser));
		http_parser_init(parser, HTTP_REQUEST); 
		http_parser_settings settings_null = 
		{
             on_message_begin : on_message_begin,
			 on_url : on_url,
			 on_status : 0,
			 on_header_field : on_header_field,
			 on_header_value : on_header_value,
			 on_headers_complete : on_headers_complete,
			 on_body : on_body,
			 on_message_complete : on_message_complete
		};

		http_request_t http_req;
		init_http_request(&http_req);
		parser->data = &http_req;
		int parsed = http_parser_execute(parser, &settings_null, buff, expect_len);
		printf("real parsed:%d, method:%d, data:%llu, parser:%llu\n", parsed, parser->method, (unsigned long long)((int*)(parser->data)), (unsigned long long)(parser));
		http_req.method.method = parser->method;
		http_req.method.http_major = parser->http_major;
		http_req.method.http_minor = parser->http_minor;

		final_parse_http_req(&http_req);

		rc = do_process_http_request(ptr, &http_req);
		if(rc){
			LOG_ERR("failed to process http request:%d", rc);
			if(rc == 404){
				ack_http_repsone(ptr, 404, "Not Found", "text/html", "<p>Page Not Found\n");
			}else{
				ack_http_repsone(ptr, 500, "Internal Server Error", "text/html", "<p>Internal Server Error\n");
			}
			json_object_put(http_req.json_req_root);
		}

		free(buff);
		free(parser);

		free_http_request_extra_info(&http_req);
	}

	return 0;
}

int serialize_http_to_send_chain(ev_ptr_t* ptr, coroutine_t* co, int ret_code, ::google::protobuf::Message* msg, const char* err_msg)
{
	json_object* js = json_object_new_object(); 
	if(NULL == js){
		LOG_ERR("failed to new js object");
		return -1;
	}

	json_object* body_code = json_object_new_int(ret_code);
	json_object_object_add(js, "code", body_code);

	json_object* body_msg = json_object_new_string(err_msg?err_msg:"");
	json_object_object_add(js, "msg", body_msg);

	if(!ret_code){
		int array = 0;
		json_object* body_data = util_parse_json_from_pb(msg, &array);
		if(body_data){
			if(!array){
				json_object* shit = json_object_new_int(0);
				json_object_object_add(body_data, "_gt_", shit);
			}
			json_object_object_add(js, "data", body_data);
		}
	}

	if(co->proto_user_ctx){
		json_object* pb_svr = util_parse_json_from_pb((blink::UserContext*)(co->proto_user_ctx));
		json_object_object_add(js, "pb_svr", pb_svr);
	}

	const char* str = json_object_to_json_string(js);
	size_t len = strlen(str);

	add_http_response_code(ptr, 200, "OK");
	add_http_response_header(ptr, "Content-Type", "application/json");

	char tmp[64];
	snprintf(tmp, 64, "%" PRIu64, len);
	add_http_response_header(ptr, "Content-Length", tmp);
	add_http_response_header(ptr, "Server", g_app_name);

	//time_t now = time(NULL);
	//add_http_response_header(ptr, "Expires", ctime(&now));

	add_http_response_content(ptr, str);

	json_object_put(js);
	return 0;
}



