#include <http_client.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <string.h>
#include <map>
#include <vector>
#include <errno.h>
#include <string>
#include <stdio.h>

extern int  g_svr_exit;
static int curl_sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp);
static int curl_multi_timer_cb(CURLM *multi, long timeout_ms, http_client_t* hc);
static void on_recv_new_request(http_client_t* hc);
static void on_recv_timer_event(http_client_t* hc);
static void on_recv_sock_ev(http_client_t* hc, epoll_event* ev);
static void notify_hc_client(http_client_t* hc);
static int set_curl_opt(http_client_t* hc, http_request_t* hr, CURL* easy);
static void check_multi_info(http_client_t* hc);
static void fin_http_2_worker(http_request_t* hr, int code, const char* err_msg);

http_client_t* malloc_http_client()
{
	http_client_t* hc = (http_client_t*)calloc(1, sizeof(http_client_t));
	hc->epfd = epoll_create(1024);

	hc->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	struct itimerspec its;
	memset(&its, 0, sizeof(struct itimerspec));
	//its.it_interval.tv_sec = 1;
	//its.it_value.tv_sec = 1;
	timerfd_settime(hc->tfd, 0, &its, NULL);
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = hc->tfd;
	epoll_ctl(hc->epfd, EPOLL_CTL_ADD, hc->tfd, &ev);

	pipe(hc->pipefd);
	ev.data.fd = hc->pipefd[0];
	epoll_ctl(hc->epfd, EPOLL_CTL_ADD, hc->pipefd[0], &ev);

	hc->multi = curl_multi_init();
	curl_multi_setopt(hc->multi, CURLMOPT_SOCKETFUNCTION, curl_sock_cb);
	curl_multi_setopt(hc->multi, CURLMOPT_SOCKETDATA, hc);
	curl_multi_setopt(hc->multi, CURLMOPT_TIMERFUNCTION, curl_multi_timer_cb);
	curl_multi_setopt(hc->multi, CURLMOPT_TIMERDATA, hc);

	INIT_LIST_HEAD(&hc->hrs);
	pthread_mutex_init(&(hc->lock), NULL);
	hc->url_breakers = new std::map<std::string, circuit_breaker_t*>() ;
	return hc;
}

static void* run_hc_thread(void* arg)
{
	pthread_detach(pthread_self());
	http_client_t* hc = (http_client_t*)arg;
	struct epoll_event events[10];
	int n = 0;
	struct epoll_event* ev = NULL;
	while(!g_svr_exit){
		n = epoll_wait(hc->epfd, events, sizeof(events)/sizeof(struct epoll_event), 10000);
		for(int i = 0; i < n; ++i){
			ev = events + i;
			if(ev->data.fd == hc->pipefd[0]){
				on_recv_new_request(hc);
				continue;
			}

			if(ev->data.fd == hc->tfd){
				on_recv_timer_event(hc);
				continue;
			}

			on_recv_sock_ev(hc, ev);
		}
	}

	curl_multi_cleanup(hc->multi);
	return NULL;
}

void run_http_client(http_client_t* hc)
{
	pthread_create(&hc->pth, NULL, run_hc_thread, hc);
}

void free_http_request(http_request_t* hr)
{
	if(!hr){
		return;
	}

	if(hr->post_params){
		free(hr->post_params);
	}

	free(hr);
}

int invoke_http_request(rpc_ctx_t* ctx, blink::req_http* req, blink::rsp_http* rsp, http_info_t* info)
{
	if(!ctx || !req || !rsp){
		LOG_ERR("ctx, req or rsp is null");
		return 0;
	}


	http_client_t* hc = ((worker_thread_t*)(ctx->co->worker))->hc;
	http_request_t* hr = (http_request_t*)calloc(1, sizeof(http_request_t));
	hr->ctx = ctx;
	hr->req = req;
	hr->rsp = rsp;
	hr->info = info;
	INIT_LIST_HEAD(&hr->list);

	pthread_mutex_lock(&hc->lock);
	list_add_tail(&hr->list, &hc->hrs);
	pthread_mutex_unlock(&hc->lock);

	notify_hc_client(hc);
	co_yield(ctx->co);
	LOG_DBG("req:%s rsp:%s", req->ShortDebugString().data(), rsp->ShortDebugString().data());
	return 0;
}

static void set_sock(http_sock_info_t* hs, curl_socket_t s, CURL *e, int act, http_client_t* hc)
{
	//printf("%llu %llu set sock:%d\n", pthread_self(), get_monotonic_milli_second(), s);
	struct epoll_event ev;
	int kind = (act & CURL_POLL_IN ? EPOLLIN : 0) | (act & CURL_POLL_OUT ? EPOLLOUT : 0);
	if(hs->sockfd){
		epoll_ctl(hc->epfd, EPOLL_CTL_DEL, hs->sockfd, NULL);
	}

	hs->sockfd = s;
	hs->easy = e;
	hs->action = act;

	ev.events = kind; 
	ev.data.fd = s;
	epoll_ctl(hc->epfd, EPOLL_CTL_ADD, s, &ev);
}

static void rm_sock(http_sock_info_t* hs, http_client_t* hc)
{
	if(!hs){
		return;
	}

	//printf("%llu %llu rm sock:%d\n", pthread_self(), get_monotonic_milli_second(), hs->sockfd);
	if(hs->sockfd){
		epoll_ctl(hc->epfd, EPOLL_CTL_DEL, hs->sockfd, NULL);
	}

	free(hs);
}

static void add_sock(curl_socket_t s, CURL *easy, int action, http_client_t* hc)
{
	//printf("%llu %llu add sock:%d\n", pthread_self(), get_monotonic_milli_second(), s);
	http_sock_info_t* hs = (http_sock_info_t*)calloc(1, sizeof(http_sock_info_t));
	hs->hc = hc;
	set_sock(hs, s, easy, action, hc);
	curl_multi_assign(hc->multi, s, hs);
}

static int curl_sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
	http_client_t* hc = (http_client_t*)cbp;
	http_sock_info_t* hs = (http_sock_info_t*)sockp;
	if(what == CURL_POLL_REMOVE) {
		rm_sock(hs, hc);
		return 0;
	}

	if(!hs){
		add_sock(s, e, what, hc);
		return 0;
	}

	set_sock(hs, s, e, what, hc);
	return 0;
}

static int curl_multi_timer_cb(CURLM *multi, long timeout_ms, http_client_t* hc)
{
	if(!timeout_ms){
		curl_multi_socket_action(hc->multi, CURL_SOCKET_TIMEOUT, 0, &hc->still_running);
		//printf("%llu %llu multi timer no timeout, still running:%d\n", pthread_self(), get_monotonic_milli_second(), hc->still_running);
		check_multi_info(hc);
		return 0;
	}

	//printf("%llu %llu multi timer cb:%ld\n", pthread_self(), get_monotonic_milli_second(), timeout_ms);
	struct itimerspec its;
	memset(&its, 0, sizeof(struct itimerspec));
	if(timeout_ms>0){
		its.it_interval.tv_sec = 1;
		its.it_interval.tv_nsec = 0;
		its.it_value.tv_sec = timeout_ms / 1000;
		its.it_value.tv_nsec = (timeout_ms % 1000) * 1000;
	}/*else{
		its.it_interval.tv_sec = 1;
		its.it_value.tv_sec = 1;
	}*/

	timerfd_settime(hc->tfd, /*flags=*/0, &its, NULL);
	return 0;
}

static void on_recv_new_request(http_client_t* hc)
{
	int k = 0;
	read(hc->pipefd[0], &k, sizeof(k));
	while(!list_empty(&hc->hrs)){
		pthread_mutex_lock(&hc->lock);
		list_head* p = pop_list_node(&hc->hrs);
		pthread_mutex_unlock(&hc->lock);

		http_request_t* hr = list_entry(p, http_request_t, list);
		CURL *easy = curl_easy_init();
		if(!easy){
			fin_http_2_worker(hr, CURLE_FAILED_INIT, "failed to init curl");
			free_http_request(hr);
			continue;
		}

		int rc = set_curl_opt(hc, hr, easy);
		if(rc){
			curl_easy_cleanup(easy);
			fin_http_2_worker(hr, rc, "failed to set curl opt");
			free_http_request(hr);
			continue;
		}

		//printf("%llu %llu recv new request\n", pthread_self(), get_monotonic_milli_second());
		//add_handle--->callback multi_timer_cb-->curl connect-->callback socket_cb-->add_2_epoll-->event_cb-->socket_action--->callback writecb
		curl_multi_add_handle(hc->multi, easy);
	}
}

static void on_recv_timer_event(http_client_t* hc)
{
	uint64_t count = 0;
	ssize_t err = read(hc->tfd, &count, sizeof(uint64_t));;  
	if(err==-1 && errno == EAGAIN){
		return;
	}

	//printf("%llu %llu recv timer event\n", pthread_self(), get_monotonic_milli_second());
	curl_multi_socket_action(hc->multi,CURL_SOCKET_TIMEOUT, 0, &hc->still_running);
	check_multi_info(hc);
}

static void on_recv_sock_ev(http_client_t* hc, epoll_event* ev)
{
	int revents = ev->events;
	int action = (revents & EPOLLIN ? CURL_POLL_IN : 0) | (revents & EPOLLOUT ? CURL_POLL_OUT : 0);
	curl_multi_socket_action(hc->multi, ev->data.fd, action, &hc->still_running);
	check_multi_info(hc);
	if(hc->still_running > 0) {
		return;
	}

	//printf("%llu %llu recv sock event\n", pthread_self(), get_monotonic_milli_second());

	struct itimerspec its;
	memset(&its, 0, sizeof(struct itimerspec));
	//its.it_interval.tv_sec = 1;
	//its.it_value.tv_sec = 1;
	timerfd_settime(hc->tfd, 0, &its, NULL); 
}

static void notify_hc_client(http_client_t* hc)
{
	int k = 1;
	write(hc->pipefd[1], &k, sizeof(k));
}


static size_t write_data(void* buffer,size_t size,size_t nmemb,void *data)
{
	//printf("%llu %llu write data:%llu\n", pthread_self(), get_monotonic_milli_second(), size*nmemb);
	 http_request_t* hr = (http_request_t*)data;
	 if(!hr->rsp){
		 return size*nmemb;
	 }

	 std::string* content = hr->rsp->mutable_content();
	 content->append((char*)buffer, size*nmemb);
	 return (size * nmemb);
}

static void encode_map(CURL *curl, std::map<std::string, std::string>& params, std::string& ret)
{
	for (std::map<std::string, std::string>::iterator iter = params.begin(); iter != params.end(); ++iter)
	{
		if(!ret.empty()){
			ret.append("&");
		}
		ret.append(iter->first);
		ret.append("=");
		char* encode = curl_easy_escape(curl, iter->second.c_str(), iter->second.size());
		if(encode){
			ret.append(encode);
			curl_free(encode);
		}else{
			ret.append(iter->second);
		}
	}
}

static void build_http_query(CURL *curl, std::map<std::string, std::string>& params, std::string& ret)
{
	for (std::map<std::string, std::string>::iterator iter = params.begin(); iter != params.end(); ++iter)
	{
		if(!ret.empty()){
			ret.append("&");
		}
		ret.append(iter->first);
		ret.append("=");
		ret.append(iter->second);
		ret.append("&");
	}
}

static std::string get_sign(CURL *curl, blink::req_http* req, std::map<std::string, std::string>& params)
{
	std::string str; 
	encode_map(curl, params, str);
	str.append(req->app_secret());

	LOG_DBG("[get_sign] str: %s", str.c_str());

	unsigned char md5[MD5_DIGEST_LENGTH] = "";	
	md5_sum(str.c_str(), str.size(), md5);

	char sign[33] = "";
	transform_md5(md5, sign);

	return std::string((const char*)sign);
}

static void get_params(CURL *curl, blink::req_http* req, std::string& params_str)
{
	// 为了拼接参数做md5 -> sign
	// 把接口所有POST参数拼接（sign参数除外），如appkey=xx&ts=xx，按参数名称排序，最后再拼接上密钥AppSecret，做md5加密。
	std::map<std::string, std::string> params;
	bool is_appkey = req->has_app_key();
	if (is_appkey)
		params.insert(std::pair<std::string, std::string>("appkey", req->app_key()));

	for (int i = 0; i < req->keys_size(); ++i)
		params.insert(std::pair<std::string, std::string>(req->keys(i), req->vals(i)));

	if (is_appkey){
		char tmp[120];
		snprintf(tmp, sizeof(tmp), "%" PRIu64, time(NULL));
		params.insert(std::pair<std::string, std::string>("ts", std::string(tmp)));
	}

	if (is_appkey)
		params.insert(std::pair<std::string, std::string>("sign", get_sign(curl, req, params)));

	if (req->need_escape()){
		encode_map(curl, params, params_str);	
	}else{
		build_http_query(curl, params, params_str);	
	}
}

static circuit_breaker_t* get_breaker_by_url(const std::string& url, std::map<std::string, circuit_breaker_t*>* url_breakers)
{
	std::map<std::string, circuit_breaker_t*>::iterator it = url_breakers->find(url);
	if(it != url_breakers->end()){
		return it->second;
	}

	circuit_breaker_t* breaker = malloc_circuit_breaker(10,10, 10);
	url_breakers->insert(std::pair<std::string, circuit_breaker_t*>(url, breaker));
	return breaker;
}

static int set_curl_opt(http_client_t* hc, http_request_t* hr, CURL* easy)
{
	rpc_ctx_t* ctx = hr->ctx;
	blink::req_http* req = hr->req;

    if (req->uri().empty()){
		return CURLE_URL_MALFORMAT;
    }

	// Check key & val match
	if (req->keys_size() != req->vals_size()){
		return CURLE_UNSUPPORTED_PROTOCOL;
	}

    std::string url = req->uri();
	std::map<std::string, circuit_breaker_t*>* url_breakers = hc->url_breakers;
	circuit_breaker_t* breaker = get_breaker_by_url(url, url_breakers);
	if(breaker && (!check_in_circuit_breaker(breaker))){
		LOG_ERR("[http_proxy_ALARM][%s]@url circuit breaker failed. code:1, trace_id:%s, uid:%llu", url.data(), ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid); 
		return CURLE_OBSOLETE40;
	}

	// init
    CURL *curl = easy;
	std::string params_str;
	get_params(curl, req, params_str);

	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION, write_data); //对返回的数据进行操作的函数地址
	curl_easy_setopt(curl,CURLOPT_WRITEDATA, hr);
	curl_easy_setopt(curl,CURLOPT_POST, req->method() == blink::HTTP_POST); //设置问非0表示本次操作为post
	if (req->method() == blink::HTTP_GET){
		url.append("?");
		url.append(params_str);
		curl_easy_setopt(curl,CURLOPT_URL, url.c_str()); //url地址
	}else if (req->method() == blink::HTTP_POST){
		if (req->content_type() == blink::CONTENT_TYPE_JSON){
			url.append("?");
			url.append(params_str);

			hr->headers = curl_slist_append(hr->headers, "Content-Type:application/json");
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hr->headers);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->raw_data().c_str()); //设置问非0表示本次操作为post
			//curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req->raw_data().size()); 
		}else{
			hr->post_params = strdup(params_str.data());
			curl_easy_setopt(curl,CURLOPT_POSTFIELDS, hr->post_params); //设置问非0表示本次操作为post
			//curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, params_str.size()); 
		}
		curl_easy_setopt(curl,CURLOPT_URL, url.c_str()); //url地址
	}
	LOG_DBG("[do_blink_http_proxy_invoke] url: %s", url.c_str());
	curl_easy_setopt(curl, CURLOPT_HEADER, 0); //将响应头信息和相应体一起传给write_data
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); // 多线程屏蔽信号
    int connect_timeout = req->conn_timeout();
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout);
    int read_timeout = req->read_timeout();
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, read_timeout);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, hr->error);
	curl_easy_setopt(curl, CURLOPT_PRIVATE, hr);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

	// upload file
	struct curl_httppost* lastptr = NULL;
	struct curl_httppost* formpost = NULL;
	for (int i = 0; i < req->files_size(); ++i)
		curl_formadd(&formpost, &lastptr, CURLFORM_PTRNAME, req->files(i).key_name().c_str(), CURLFORM_FILE, req->files(i).file_path().c_str(), CURLFORM_END);
	if (req->files_size() > 0 )
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	// End upload file

	return 0;
}

static void check_url_breaker(http_client_t* hc, http_request_t* hr, CURLcode res)
{
	if(!hc || !hr || !hr->req || hr->req->uri().empty()){
		return;
	}

	if(hr->rsp){
		hr->rsp->set_code(res);
		if(res != CURLE_OK){
			hr->rsp->set_err_msg(curl_easy_strerror(res));
		}
	}

	circuit_breaker_t* br = get_breaker_by_url(hr->req->uri(), hc->url_breakers);
	if(!br){
		return;
	}
	if(res != CURLE_OK){
		fail_circuit_breaker(br);
	}else{
		succ_circuit_breaker(br);
	}
}

static void check_multi_info(http_client_t* hc)
{
	char *eff_url;
	CURLMsg *msg;
	int msgs_left;
	http_request_t* hr;
	CURL *easy; 
	CURLcode res;
	while((msg = curl_multi_info_read(hc->multi, &msgs_left))) { 
		if(msg->msg == CURLMSG_DONE) {
			easy = msg->easy_handle;
			res = msg->data.result;
			curl_easy_getinfo(easy, CURLINFO_PRIVATE, &hr);
			curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);

			if(res == CURLE_OK && hr->info){
				char* local_ip = NULL;
				char* remote_ip = NULL;
				curl_easy_getinfo(easy, CURLINFO_LOCAL_IP, &local_ip);
				curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &remote_ip);
				curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &(hr->info->total_cost));
				local_ip?strncpy(hr->info->local_ip, local_ip, sizeof(hr->info->local_ip)):0;
				remote_ip?strncpy(hr->info->remote_ip, remote_ip, sizeof(hr->info->remote_ip)):0;
				curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &hr->info->response_code);
			}
			//printf("%llu %llu msg done:%s\n", pthread_self(), get_monotonic_milli_second(), eff_url);
			curl_multi_remove_handle(hc->multi, easy);
			curl_easy_cleanup(easy);
			check_url_breaker(hc, hr, res);
			fin_http_2_worker(hr, res, hr->error);
			free_http_request(hr);
		}
	}
}

static void fin_http_2_worker(http_request_t* hr, int code, const char* err_msg)
{
	blink::rsp_http* rsp = hr->rsp;
	if(!rsp){
		return;
	}

	rsp->set_code(code);
	if(err_msg)rsp->set_err_msg(err_msg);
	cmd_t cmd;
	cmd.cmd = K_CMD_NOTIFY_ASYNC_HTTP_FIN;
	cmd.arg = hr->ctx;
	worker_thread_t* worker = (worker_thread_t*)(hr->ctx->co->worker);
	if(notify_worker(worker, cmd)){
		LOG_ERR("[ALARM]FATAL!!!! failed to notify worker");
	}
}

void async_fin_http_request(rpc_ctx_t* ctx)
{
	LOG_DBG("fin http request");
	coroutine_t* co = ctx->co;
	co_resume(co);
	co_release(&co);
}
