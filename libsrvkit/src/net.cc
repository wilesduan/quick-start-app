
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net.h>
#include <set>

#include <server_inner.h>
#include <http2_client.h>

#define K_PACKAGE_TIME_CHECK 5

static bool g_ssl_init = false;
extern char* g_app_name;

static int do_read_msg_from_tcp(void* arg);
static void yield_accept(ev_ptr_t* ptr, int accept_strategy);
static int notify_accept(worker_thread_t* next, listen_t* lt);

static int do_accept_fd(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(NULL == worker){
		LOG_ERR("NULL worker");
		return -1;
	}

	listen_t* lt = (listen_t*)(ptr->listen);
	server_t* server = (server_t*)worker->mt;

	sockaddr_in addr;
	socklen_t addr_len = sizeof(sockaddr_in);
	int num = 0;
	while(num++ < lt->accept_num_before_yield){
		int fd = accept(ptr->fd, (sockaddr*)&addr, &addr_len);
		if(fd < 0){
		    LOG_ERR("accept error,return value:%d", fd);
		    MONITOR_ACC("sys_accept_error", 1);
			break;
		}

		MONITOR_ACC("sys_accept", 1);

		util_fcntl(fd);

		//TODO check addr
		if(worker->conns > server->max_conns_per_worker){
			LOG_ERR("too many conns. close fd.");
			close(fd);
			continue;
		}

		++worker->conns;
		ev_ptr_t* newptr = get_ev_ptr(worker, fd);
		INIT_LIST_HEAD(&newptr->co_list);

		newptr->do_read_ev = do_read_msg_from_tcp;
		newptr->fd = fd;

		std::string ip = util_get_peer_ip_v4(fd);
		strncpy(newptr->ip, ip.c_str(), sizeof(newptr->ip));
		newptr->port = util_get_peer_port(fd);//lt->port;

		newptr->arg = worker;
		newptr->listen = lt;
		newptr->cli = NULL;
		newptr->package_time = time(NULL);
		newptr->num_package_in_5s = 0;

		if(newptr->recv_chain){
			util_destroy_buff_chain(newptr->recv_chain);
		}
		newptr->recv_chain = util_create_buff_chain(1024);
		
		if(newptr->send_chain){
			util_destroy_buff_chain(newptr->send_chain);
		}
		newptr->send_chain = util_create_buff_chain(1024);

		if(lt->type == EN_LISTEN_HTTP){
			newptr->process_handler = process_http_request_from_ev_ptr;
		}

		newptr->ev = 0;
		add_read_ev(worker->epoll_fd, newptr);

		//CAUTION do_accept_conn could change idle_time 
		newptr->idle_time = lt->idle_time;
		if(worker->wt_fns.do_accept_conn){
			(worker->wt_fns.do_accept_conn)(newptr);
		}

		LOG_DBG("add_ev_ptr_2_idle_time_wheel worker:%llu, host:%s:%d fd:%d", (long long unsigned)worker, newptr->ip, newptr->port, newptr->fd);
		add_ev_ptr_2_idle_time_wheel(worker, newptr);
	}

	yield_accept(ptr, lt->accept_strategy);
	return 0;
}

static void do_yield_accept(ev_ptr_t* ptr, worker_thread_t* next)
{
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(worker == next){
		return;
	}

	list_head* ls = NULL;
	listen_t* lt = NULL;
	list_for_each(ls, &(worker->listens)){
		lt = list_entry(ls, listen_t, worker);
		if(lt->ptr == ptr){
			LOG_DBG("yield accept. worker:%llu, recycle_ev_ptr host:%s:%d fd:%d",(long long unsigned)worker, lt->ip, lt->port, lt->fd);
			recycle_ev_ptr(lt->ptr);
			list_del(ls);
			INIT_LIST_HEAD(ls);
			break;
		}
	}

	if(lt && notify_accept(next, lt)){
		add_one_listen(worker, lt);
		return;
	}
}

static void yield_accept(ev_ptr_t* ptr, int accept_strategy)
{
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	server_t* server = (server_t*)(worker->mt);
	/*
	worker_thread_t* next = (worker_thread_t*)(worker->next);
	while(next != worker && next->conns > server->max_conns_per_worker*7/8){
		next = (worker_thread_t*)(next->next);
	}
	*/

	//static size_t round = 0;
	//size_t idx = __sync_fetch_and_add(&round, 1);
	size_t start = (worker->idx+1) % server->num_worker;
	worker_thread_t* next = server->array_worker+start;
	for(int i = 0; accept_strategy != EN_ACCEPT_ROUND_ROBIN && i < server->num_worker; ++i){
		worker_thread_t* w = server->array_worker + ((i + start)%server->num_worker);
		switch(accept_strategy){
			case EN_ACCEPT_CONNS_LESS_FIRST:
				if(w->conns < next->conns){
					next = w;
				}
				break;
			case EN_ACCEPT_REQUEST_LESS_FIRST:
				if(w->num_request < next->num_request){
					next = w;
				}
				break;
			default:
				break;
		}
	}

	if(next == worker) return;

	do_yield_accept(ptr, next);
	//LOG_DBG("yield accept from:%llu to %llu, %s:%d fd:%d", (long long unsigned)worker, (long long unsigned)next,ptr->ip, ptr->port, ptr->fd);
}

static int set_process_handler(ev_ptr_t* ptr)
{
	blink::MsgHead head;
	init_msg_head(head);
	int len = util_get_rd_buff_len(ptr->recv_chain);
	if(len < head.ByteSize()){
		return 0;
	}

	std::vector<iovec> iovs;
	int rc = util_get_rd_buff(ptr->recv_chain, 4, iovs);
	if(rc){
		return -1;
	}

	char magic[4];
	pad_mem_with_iovecs(iovs, magic, 4);

	int n_magic = ntohl(*(int*)magic);
	rc = util_parse_pb_from_buff(head, ptr->recv_chain, head.ByteSize());
	if(rc == 0 && (head.crc() == K_PB_MAGIC || n_magic != K_SWOOLE_MAGIC)){
		ptr->process_handler = process_pb_request_from_ev_ptr;
		return 0;
	}

	if(n_magic == K_SWOOLE_MAGIC){
		ptr->process_handler = process_swoole_request_from_ev_ptr;
		return 0;
	}
	
	return -1;
}

static int do_read_msg_from_tcp(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	LOG_DBG("recv msg from %s:%d, fd:%d", ptr->ip, ptr->port, ptr->fd);
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	int num_package = 0;
	struct iovec iov;
	int fd = ptr->fd;

	while(num_package < 2){
		int rc = util_get_next_write_buff(ptr->recv_chain, &iov);
		if(rc){
			LOG_ERR("failed to get next write buff for fd:%d", ptr->fd);
			return 0;
		}

		int rcv_len = recv(fd, iov.iov_base, iov.iov_len, 0);
        if(rcv_len > 100){
            //LOG_INFO("recv big package:%llu", rcv_len);
        }

		MONITOR_ACC("sys_recv", 1);

        if(rcv_len == 0){
			LOG_DBG("peer close connection. worker:%llu recycle_ev_ptr host:%s:%d fd:%d",(long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
			shut_down_ev_ptr(ptr);
			recycle_ev_ptr(ptr);
			return 0;
		}else if(rcv_len < 0){
			LOG_DBG("recv error:%d", errno);
			return 0;
		}

		if(ptr->listen && ((listen_t*)ptr->listen)->limit){
			++ptr->num_package_in_5s;
			time_t now = time(NULL);
			if(now - ptr->package_time > K_PACKAGE_TIME_CHECK){
				ptr->num_package_in_5s = 0;
				ptr->package_time = now;
			}

			if(ptr->num_package_in_5s > ((listen_t*)ptr->listen)->limit){
				LOG_ERR("worker:%llu recv %d package from %s:%d in %d second", (long long unsigned)worker, ptr->num_package_in_5s, ptr->ip, ptr->port, now-ptr->package_time);
				shut_down_ev_ptr(ptr);
				recycle_ev_ptr(ptr);
				return 0;
			}
		}

		++num_package;
		rc = util_advance_wr(ptr->recv_chain, rcv_len);
		if(rc){
			LOG_ERR("failed to advance wr. worker:%llu recycle_ev_ptr host:%s:%d fd:%d",(long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
			shut_down_ev_ptr(ptr);
			recycle_ev_ptr(ptr);
			return 0;
		}

		LOG_DBG("add_ev_ptr_2_idle_time_wheel worker:%llu, host:%s:%d fd:%d", (long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
		del_idle_event_from_timer(&worker->timers, &(ptr->idle_time_wheel));
		add_ev_ptr_2_idle_time_wheel(worker, ptr);

		fn_process_request handler = ptr->process_handler;
		if(NULL == handler && set_process_handler(ptr)){
			LOG_ERR("no process handler. worker:%llu recycle_ev_ptr host:%s:%d fd:%d", (long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
			shut_down_ev_ptr(ptr);
			recycle_ev_ptr(ptr);
			return 0;
		}

		handler = ptr->process_handler;
		if(NULL == handler){
			return 0;
		}

		//process_pb_request_from_ev_ptr(ptr)
		rc = handler(ptr);
		if(rc){
			LOG_ERR("failed to process data package. worker:%llu recycle_ev_ptr host:%s:%d fd:%d",(long long unsigned)worker, ptr->ip, ptr->port, ptr->fd);
			shut_down_ev_ptr(ptr);
			recycle_ev_ptr(ptr);
			return 0;
		}
	}

	return 0;
}

static int do_recv_from_udp(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	if(NULL == worker){
		LOG_ERR("NULL worker");
		return 0;
	}

	listen_t* lt = (listen_t*)(ptr->listen);
	//server_t* server = (server_t*)worker->mt;

	sockaddr_in addr;
	socklen_t addr_len = sizeof(sockaddr_in);

	char recv_buff[1024*60];
	size_t buff_len = sizeof(recv_buff);
	ssize_t recv_len = recvfrom(lt->fd, recv_buff, buff_len, 0,(sockaddr*) &addr, &addr_len);
	if(recv_len <= 0){
		LOG_ERR("failed to recv udp datagram. len:%d errno:%d, error:%s", (int)recv_len, errno, strerror(errno));
		return 0;
	}

	if(recv_len >= (ssize_t)sizeof(recv_buff)){
		LOG_ERR("recv buff too long");
		return 0;
	}

	server_t* server = (server_t*)(worker->mt);
	int index = random()%(server->num_worker);
	worker_thread_t* next = server->array_worker + index;

	ev_ptr_t tmp_ptr;
	memset(&tmp_ptr, 0, sizeof(ev_ptr_t));
	tmp_ptr.tmp = 1;
	tmp_ptr.fd = ptr->fd;
	tmp_ptr.arg = worker;
	inet_ntop(AF_INET, &(addr.sin_addr), tmp_ptr.ip, sizeof(tmp_ptr.ip));
	tmp_ptr.port = ntohs(addr.sin_port);
	INIT_LIST_HEAD(&(tmp_ptr.heartbeat_wheel));
	INIT_LIST_HEAD(&(tmp_ptr.idle_time_wheel));
	INIT_LIST_HEAD(&(tmp_ptr.co_list));
	INIT_LIST_HEAD(&tmp_ptr.free_ev_ptr_list);
	INIT_LIST_HEAD(&(tmp_ptr.async_req_out_list));

	do_yield_accept(ptr, next);

	//yield_accept(ptr);

	if(recv_len > (int)sizeof(swoole_head_t)){
		swoole_head_t swoole_head;
		memcpy(&swoole_head, recv_buff, sizeof(swoole_head_t));
		swoole_head_ntohl(&swoole_head);
		if(swoole_head.header_magic == K_SWOOLE_MAGIC){
			LOG_INFO("recv swoole udp package.len:%llu", recv_len);
			process_swoole_request(&tmp_ptr, &swoole_head, recv_buff+sizeof(swoole_head_t));
			return 0;
		}
	}

	//LOG_INFO("recv udp package.len:%llu", recv_len);
	blink::MsgBody body;
	bool parse = body.ParseFromArray(recv_buff, recv_len);
	if(!parse){
		LOG_ERR("failed to parse pb");
		return 0;
	}

	process_pb_request(&tmp_ptr, body);
	fn_method fn = get_fn_method(worker, body.service().data(), body.method());
	if(!fn && server->mt_fns.do_process_udp_data){
		(server->mt_fns.do_process_udp_data)(worker, lt->fd, &body, &addr, addr_len);
	}

	return 0;
}

static void get_ip_port_from_str(const char* url, std::vector<std::pair<char*, int> >& ip_ports)
{
	const char* ip = url;
	const char* port = url;
	const char* delim = NULL;
	int n_port = 0;
	char* str_ip = NULL;

parse:
	while(*port != 0 && *port !=':'){
		++port;
	}
	if(*port == 0){
		LOG_ERR("invalid url:%s\n", url);
		return;
	}

	delim = port+1;
	while(*delim != 0 && (*delim != ',' && *delim != ';')){
		++delim;
	}
	n_port = atoi(port+1);
	if(n_port <= 0){
		LOG_ERR("invalid url:%s", url);
		return;
	}
	str_ip = strndup(ip, port-ip);
	ip_ports.push_back(std::pair<char*, int>(str_ip, n_port));

	if(*delim == 0){
		LOG_INFO("parse url done");
		return;
	}

	ip = delim+1;
	port = delim+1;
	goto parse;
}

static void get_http_ip_port_from_str(const char* url, std::vector<std::pair<char*, int> >& ip_ports)
{
	const char* p = url;
	int port = 80;
	const char* prt = url;
	while(*prt != '\0' && *prt != ':'){
		++prt;
	}

	char* ip = NULL;
	if(*prt != '\0'){
		port = atoi(prt+1);
		ip = strndup(p, prt-p);
	}else{
		ip = strdup(p);
	}

	int addr = 0;
	if(1 == inet_pton(AF_INET, ip, &addr)){
		ip_ports.push_back(std::pair<char*, int>(ip, port));
		return;
	}

	struct addrinfo hints, *res = NULL, *ressave = NULL;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char service[6];
	bzero(service, sizeof(service));
	int rc = getaddrinfo(ip, service, &hints, &res);
	if(rc){
		if(res)freeaddrinfo(res);
		free(ip);
		return;
	}

	std::vector<std::pair<char*, int> > tmp_ip_ports;
	ressave = res;
	while(res){
		if(res->ai_family == AF_INET){
			struct in_addr a = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
			const char *p = inet_ntoa(a);
			LOG_DBG("dns parse:%s:%s", url, p);
			tmp_ip_ports.push_back(std::pair<char*, int>(strdup(p), port));
			//break;
		}else{
			LOG_DBG("%s af family:%d", url, res->ai_family);
		}
		res = res->ai_next;
	}

	freeaddrinfo(ressave);
	free(ip);

	if(tmp_ip_ports.empty()){
		return;
	}

	long int rand = random()%tmp_ip_ports.size();
	ip_ports.push_back(tmp_ip_ports[rand]);

	for(size_t i = 0; i < tmp_ip_ports.size(); ++i){
		if(i != (size_t)rand && tmp_ip_ports[i].first){
			free(tmp_ip_ports[i].first);
		}
	}
}

static void get_ip_port_with_url(proto_client_t* cli, const char* url, std::vector<std::pair<char*, int> >& ip_ports)
{
	const char* p = url;
	while(*p != 0 && (*p == ' ' || *p == '\t' || *p == '\n')){
		++p;
	}

	if(strncmp(p, "zk://", 5) == 0){
		get_ip_port_from_zk(p, ip_ports);
		cli->from_zk = 1;
		return;
	}

	if(strncmp(p, "tcp://", 6) == 0){
		get_ip_port_from_str(p+6, ip_ports);
		cli->sock_type = EN_SOCK_TCP;
		return;
	}

	if(strncmp(p, "udp://", 6) == 0){
		get_ip_port_from_str(p+6, ip_ports);
		cli->sock_type = EN_SOCK_UDP;
		return;
	}
	
	if(strncmp(p, "https://", 8) == 0){
		get_http_ip_port_from_str(p+8, ip_ports);
		return;
	}

	LOG_ERR("unknown cli protocol:%s", url);
}

void init_client_inst(worker_thread_t* worker, proto_client_inst_t* cli, const std::pair<char*, int>& ip_port, int async_fd)
{
	if(cli->ptr){
		LOG_INFO("###########client is still connected. worker:%llu, host:%s:%d###################", (long long unsigned)worker, ip_port.first, ip_port.second);
		return;
	}

	if(!g_ssl_init && cli->proto_type == EN_PROTOCAL_HTTP2){
		g_ssl_init = true;
		SSL_library_init();
		SSL_load_error_strings();
	}

	strncpy(cli->ip, ip_port.first, sizeof(cli->ip)-1);
	cli->port = ip_port.second;

	int fd = async_fd > 0? async_fd : util_connect_2_svr2(cli->ip, cli->port, cli->sock_type == EN_SOCK_UDP?SOCK_DGRAM:SOCK_STREAM); 
	if(fd < 0){
		LOG_DBG("add_client_inst_2_wheel worker:%llu, depened service service:%s:%d is not in working", (long long unsigned)worker,cli->ip, cli->port);
		add_client_inst_2_wheel(worker, cli);
		return;
	}

	if(cli->proto_type == EN_PROTOCAL_HTTP2 && http2_ssl_connect(worker, cli, fd)){
		close(fd);
		add_client_inst_2_wheel(worker, cli);
		LOG_ERR("failed to construct ssl connect. %s:%d", cli->ip, cli->port);
		return;
	}

	LOG_INFO("worker:%llu connected to dep service:%s:%d fd:%d ok", (long long unsigned)(worker), cli->ip, cli->port, fd);

	ev_ptr_t* ptr = get_ev_ptr(worker, fd);
	strcpy(ptr->ip, cli->ip);
	ptr->port = cli->port;
	if(!ptr->breaker){
		ptr->breaker = malloc_circuit_breaker(10, cli->breaker_setting->failure_threshold_in_10s, cli->breaker_setting->half_open_ratio);
	}

	if(ptr->recv_chain){
		util_destroy_buff_chain(ptr->recv_chain);
	}
	ptr->recv_chain = util_create_buff_chain(1024);

	if(ptr->send_chain){
		util_destroy_buff_chain(ptr->send_chain);
	}
	ptr->send_chain = util_create_buff_chain(1024);

	ptr->fd = fd;
	ptr->arg = worker;
	cli->ptr = ptr;
	cli->ptr->cli = cli;
	cli->num_conn_failed = 0;
	cli->conn_time = time(NULL);
	ptr->udp_sock = 0;

	if(cli->sock_type == EN_SOCK_UDP){
		ptr->udp_sock = 1;
		return;
	}

	switch(cli->proto_type){
		case EN_PROTOCAL_HTTP2:
			break;
		default:
			ptr->do_read_ev = do_read_msg_from_tcp;
			ptr->ev = 0;
			add_read_ev(worker->epoll_fd, ptr);
			break;
	}


	switch(cli->proto_type){
		case EN_PROTOCAL_PB:
			ptr->process_handler = process_pb_request_from_ev_ptr;
			break;
		case EN_PROTOCAL_SWOOLE:
			ptr->process_handler = process_swoole_request_from_ev_ptr;
			break;
		case EN_PROTOCAL_HTTP2:
			ptr->process_handler =  http2_ping_mark;
			break;
		default:
			break;
	}

	async_heartbeat(worker, ptr);
	LOG_DBG("add_ev_ptr_2_heartbeat_wheel worker:%llu add host:%s:%d", (long long unsigned)worker, ptr->ip, ptr->port);
	add_ev_ptr_2_heartbeat_wheel(worker, ptr);

	LOG_DBG("add_ev_ptr_2_idle_time_wheel worker:%llu add host:%s:%d", (long long unsigned)worker, ptr->ip, ptr->port);
	if(cli->proto_type != EN_PROTOCAL_HTTP2){
		add_ev_ptr_2_idle_time_wheel(worker, ptr);
	}
}

static list_head* get_next_weight_cli_list(proto_client_t* cli)
{
	return cli->weight_array + cli->weight_idx;
}

static void put_client_inst_2_weight_list(proto_client_inst_t* inst, proto_client_t* clients, size_t idx)
{
	idx = idx%K_CLI_WEIGHT_SIZE;
	list_del(&inst->weight_list);
	list_add(&inst->weight_list, clients->weight_array+idx);
	clients->weight_bitmap |= (((uint64_t)1)<<idx);
}

static void remove_client_from_weight_list(proto_client_inst_t* inst, proto_client_t* clients, size_t idx)
{
	idx = idx%K_CLI_WEIGHT_SIZE;
	list_del(&inst->weight_list);
	INIT_LIST_HEAD(&inst->weight_list);
	list_head* list = clients->weight_array + idx;
	if(!list_empty(list)){
		return;
	}

	clients->weight_bitmap &= (~(((uint64_t)1)<<idx));
}

static size_t get_next_nonempty_idx(proto_client_t* clients)
{
	size_t idx = clients->weight_idx;
	uint64_t mask = ~((((uint64_t)1)<<idx)-1);
	uint64_t tmp = (clients->weight_bitmap&mask)>>idx;
	size_t offset = 0;
	if(tmp){
		offset = idx;
	}else{
		tmp = clients->weight_bitmap;
	}

	if(!(tmp & 0xffffffff)){
		offset += 32;
		tmp >>= 32;
	}
	if(!(tmp & 0xffff)){
		offset += 16;
		tmp >>= 16;
	}

	if(!(tmp & 0xff)){
		offset += 8;
		tmp >>= 8; 
	}

	if(!(tmp & 0xf)){
		offset += 4;
		tmp >>= 4;
	}
	
	if(!(tmp & 3)){
		offset += 2;
		tmp >>= 2;
	}

	if(!(tmp & 1)){
		offset += 1;
		tmp >>= 1;
	}

	return offset;
}


static proto_client_t* get_proto_client_with_config(worker_thread_t* worker, const blink::pb_dep_service& inst)
{
	if(!inst.name().size()){
		LOG_ERR("dep_service item miss service name");
		return NULL;
	}

	if(!inst.url().size()){
		LOG_ERR("dep_service item miss service url");
		return NULL;
	}

	const char* service = inst.name().data();
	const char* url = inst.url().data();

	proto_client_t* cli = (proto_client_t*)calloc(1, sizeof(proto_client_t));
	if(NULL == cli){
		return NULL;
	}
	INIT_LIST_HEAD(&(cli->list));
	cli->service = strdup(service);
	cli->url = strdup(url);
	cli->hash = inst.hash();
	cli->timeout = inst.timeout(); 
	cli->req_queue_size = inst.req_queue_size(); 
	cli->breaker_setting.failure_threshold_in_10s = inst.failure_in_10s();
	cli->breaker_setting.half_open_ratio  = inst.half_open_ratio();
	cli->breaker_setting.open = (inst.has_failure_in_10s()|| inst.has_half_open_ratio())?1:0;
	cli->proto_type = EN_PROTOCAL_PB;
	cli->sock_type = EN_SOCK_TCP;
	cli->ssl_cert_path = inst.ssl_cert().size()?strdup(inst.ssl_cert().data()):NULL;
	cli->ssl_cert_key = inst.ssl_key().size()?strdup(inst.ssl_key().data()):NULL;
	if(inst.has_type()){
		const char* type = inst.type().data();
		if(strcmp(type, "swoole") == 0){
			cli->proto_type = EN_PROTOCAL_SWOOLE;
		}else if(strcmp(type, "http2") == 0){
			cli->proto_type = EN_PROTOCAL_HTTP2;
		}
	}

	cli->load_balance = EN_LOAD_BALANCE_ROUND_ROBIN;
	if(inst.has_load_balance()&& strcmp(inst.load_balance().data(), "weight") == 0){
		cli->load_balance = EN_LOAD_BALANCE_WEIGHT;
	}

	for(int i = 0; i < K_CLI_WEIGHT_SIZE; ++i){
		list_head* item = cli->weight_array+i;
		INIT_LIST_HEAD(item);
	}
	cli->weight_idx = 0;

	if(inst.has_sock()){
		const char* sock = inst.sock().data();
		if(sock && strcmp(sock, "udp") == 0){
			cli->sock_type = EN_SOCK_UDP;
		}
	}

	std::vector<std::pair<char*, int> > ip_ports;
	get_ip_port_with_url(cli, url, ip_ports);
	if(ip_ports.size() == 0){
		LOG_DBG("no ip ports in %s", cli->url);
		return cli;
	}

	cli->num_clients = ip_ports.size();
	cli->cli_inst_s = (proto_client_inst_t*)calloc(cli->num_clients, sizeof(proto_client_inst_t));
	LOG_DBG("service:%s num clients:%d\n", cli->service, cli->num_clients);
	for(size_t i = 0; i < cli->num_clients; ++i){
		(cli->cli_inst_s+i)->service = cli->service;
		(cli->cli_inst_s+i)->timeout = cli->timeout;
		(cli->cli_inst_s+i)->proto_type = cli->proto_type;
		(cli->cli_inst_s+i)->sock_type = cli->sock_type;
		(cli->cli_inst_s+i)->req_queue_size = cli->req_queue_size;
		(cli->cli_inst_s+i)->breaker_setting = &cli->breaker_setting;
		INIT_LIST_HEAD(&(cli->cli_inst_s+i)->disconnected_client_wheel);
		if(cli->proto_type == EN_PROTOCAL_HTTP2 ){
			(cli->cli_inst_s+i)->ssl_cert_path = cli->ssl_cert_path;
			(cli->cli_inst_s+i)->ssl_cert_key = cli->ssl_cert_key;
		}

		init_client_inst(worker, cli->cli_inst_s+i, ip_ports[i], -1);

		(cli->cli_inst_s+i)->weight = 1;
		INIT_LIST_HEAD(&(cli->cli_inst_s+i)->weight_list);
		put_client_inst_2_weight_list(cli->cli_inst_s+i, cli, 0);
	}

	for(size_t i = 0; i < ip_ports.size(); ++i){
		free(ip_ports[i].first);
	}

	return cli;
}

void add_dep_service(worker_thread_t* wt, const blink::pb_config* pb_config)
{
	if(!pb_config->dep_service_size()){
		return;
	}

	unsigned size = pb_config->dep_service_size();
	for(unsigned i = 0; i < size; ++i){
		const blink::pb_dep_service& dep_service = pb_config->dep_service(i);
		proto_client_t* clis = get_proto_client_with_config(wt, dep_service);
		if(NULL == clis){
			continue;
		}

		list_add(&(clis->list), &(wt->dep_service));
	}
}

static int add_tcp_port(server_t* server, listen_paramter_t* parameters)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0){
		LOG_ERR("failed to create sokect for port:%d", parameters->port);
		return -1;
	}

	int rc = 0;
	if(strcmp(parameters->sz_type, "evip") == 0){
		rc = util_set_socket_and_bind(sock, "0.0.0.0", parameters->port);
	}else{
		rc = util_set_socket_and_bind(sock, parameters->ip, parameters->port);
	}

	if(rc){
		LOG_ERR("failed to bind tcp port:%d", parameters->port);
		close(sock);
		return -2;
	}

	listen(sock, 10240);

	listen_t* tl = (listen_t*)calloc(1, sizeof(listen_t));
	INIT_LIST_HEAD(&(tl->list));
	INIT_LIST_HEAD(&(tl->worker));

	tl->type = EN_LISTEN_TCP;
	strncpy(tl->ip, parameters->ip, sizeof(tl->ip));
	tl->port = parameters->port;
	tl->fd = sock;
	tl->do_epoll_ev = do_accept_fd;
	tl->accept_strategy = parameters->accept_strategy;
	if(parameters->_public){
		tl->tag |= 1;
	}
	tl->limit = parameters->limit;
	
	tl->heartbeat = parameters->heartbeat;
	tl->accept_num_before_yield = parameters->acc_num;
	tl->idle_time = parameters->idle;
	if(parameters->services.count){
		tl->count = parameters->services.count;
		tl->lt_services= (char**)calloc(tl->count, sizeof(char*));
		for(int i = 0; i < tl->count; ++i){
			tl->lt_services[i] = strdup((parameters->services).data[i]);
		}
	}

	list_add(&(tl->list), &(server->listens));
	return 0;
}

static int add_udp_port(server_t* server,listen_paramter_t* parameters) 
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		return -1;
	}

	int rc = util_set_socket_and_bind(sock, parameters->ip, parameters->port);
	if(rc){
		LOG_ERR("failed to bind udp port:%d", parameters->port);
		close(sock);
		return -2;
	}

	listen_t* tl = (listen_t*)calloc(1, sizeof(listen_t));
	INIT_LIST_HEAD(&(tl->list));
	INIT_LIST_HEAD(&(tl->worker));

	tl->type = EN_LISTEN_UDP;
	strncpy(tl->ip, parameters->ip, sizeof(tl->ip));
	tl->port = parameters->port;
	tl->fd = sock;
	tl->do_epoll_ev = do_recv_from_udp;
	tl->accept_num_before_yield = parameters->acc_num;
	tl->idle_time = parameters->idle;

	tl->heartbeat = parameters->heartbeat;
	tl->accept_strategy = parameters->accept_strategy;
	if(parameters->services.count){
		tl->count = parameters->services.count;
		tl->lt_services = (char**)calloc(tl->count, sizeof(char*));
		for(int i = 0; i < tl->count; ++i){
			tl->lt_services[i] = strdup(parameters->services.data[i]);
		}
	}
	
	list_add(&(tl->list), &(server->listens));
	return 0;
}

static int add_http_port(server_t* server, listen_paramter_t* parameters)
{
	int rc = add_tcp_port(server, parameters);
	if(rc){
		LOG_ERR("failed to listen to http:%s:%s:%d", parameters->sz_type, parameters->ip, parameters->port);
		return rc;
	}

	list_head* p = server->listens.next;
	listen_t* tl = list_entry(p, listen_t, list);
	tl->type = EN_LISTEN_HTTP;
	return 0;
}

static void get_listen_ip(ifip_t* ifip, const char* ifname, char* sz_ip)
{
	if(NULL == ifip || NULL == ifname || strlen(ifname) == 0){
		strcpy(sz_ip, "0.0.0.0");
		return;
	}

	while(ifip){
		if(strcmp(ifname, ifip->ifi_name) == 0){
			strcpy(sz_ip, ifip->ip);
			return;
		}

		ifip = ifip->next;
	}

	LOG_ERR("no ifname equals:%s then listen 0.0.0.0 instead\n", ifname);
	strcpy(sz_ip, "0.0.0.0");
}

static void parse_parameters(const char* params, listen_paramter_t* parameters)
{
	const char* start = params;
	const char* p = start;
	const char* equal = NULL;
	const char* s1 = NULL;
	const char* s2 = NULL;
	std::vector<char*> servs;
	size_t i = 0;

parse:
	while(*p != 0 && *p != '&'){
		if(*p == '='){
			equal = p;
		}
		++p;
	}

	if(NULL == equal){
		goto next;
	}

	if(strncmp(start, "heartbeat", equal-start) == 0){
		parameters->heartbeat = atoi(equal+1);
	}else if(strncmp(start, "public", equal-start) == 0){
		parameters->_public = atoi(equal+1);
	}else if(strncmp(start, "limit", equal-start) == 0){
		parameters->limit=atoi(equal+1);
	}else if(strncmp(start, "acc_type", equal-start) == 0){
		if(strncmp(equal+1, "round", 5) == 0){
			parameters->accept_strategy = EN_ACCEPT_ROUND_ROBIN;
		}else if(strncmp(equal+1, "conns", 5) == 0){
			parameters->accept_strategy = EN_ACCEPT_CONNS_LESS_FIRST;
		}else if(strncmp(equal+1, "reqst", 5) == 0){
			parameters->accept_strategy = EN_ACCEPT_REQUEST_LESS_FIRST;
		}
	}else if(strncmp(start, "acc_num", equal-start) == 0){
		parameters->acc_num = atoi(equal+1);
		if(parameters->acc_num <= 0){
			parameters->acc_num = 1;
		}
	}else if(strncmp(start, "idle_time", equal-start) == 0){
		parameters->idle = atoi(equal+1);
		if(parameters->idle <= 0){
			parameters->idle = K_DEFALUT_IDLE_TIME;
		}

		if(parameters->idle >= K_MAX_TIMEOUT){
			parameters->idle = K_MAX_TIMEOUT-1;
		}
	}else if(strncmp(start, "services", equal-start) == 0){
		s1 = s2 = equal + 1;

parse_service:
		while(s2 != p && *s2 != ','){
			++s2;
		}
		if(s2 != s1){
			servs.push_back(strndup(s1, s2-s1));
		}
		if(s2 != p){
			s1 = s2 = s2+1;
			goto parse_service;
		}else{
			parameters->services.count = (int)servs.size();
			parameters->services.data = (char**)calloc(servs.size(), sizeof(char*));
			for(i = 0; i < servs.size(); ++i){
				(parameters->services).data[i] = servs[i];
			}
		}

	}

next:
	if(*p == 0){
		return;
	}

	start = p = p+1;
	equal = NULL;
	goto parse;
}

static int parse_listen_url(const char* url, listen_paramter_t* paremters) 
{
	if(NULL == url){
		return -1;
	}
	const char* start = url;
	while(*start != 0 && (*start ==' ' || *start == '\t' || *start == '\n')){
		++start;
	}
	const char* p = strstr(start, "://");
	if(NULL == p || p - start > K_PROTOCOL_MAX_LEN){
		return -2;
	}
	snprintf(paremters->sz_type, p-start+1, "%s", start);
	(paremters->sz_type)[p-start] = 0;

	start = p+3;
	p = start;
	p = strstr(start, ":");
	if(NULL == p || p - start > K_IFN_MAX_LEN){
		return -3;
	}
	snprintf(paremters->sz_ifn, p-start+1, "%s", start);
	(paremters->sz_ifn)[p-start] = 0;

	start = p+1;
	p = start;

	paremters->port = atoi(start);
	p = strstr(start, "?");
	if(NULL == p){
		return 0;
	}

	parse_parameters(p+1, paremters);

	return 0;
}


int do_listen(server_t* server)
{
	if(!server->pb_config->listen_size()){
		printf("no listen\n");
		return -1;
	}

	ifip_t* ifips = util_get_local_ifip();
	unsigned size = server->pb_config->listen_size(); 
	for(unsigned i = 0; i < size; ++i){
		const char* url = server->pb_config->listen(i).data();
		listen_paramter_t paremters;
		bzero(&paremters, sizeof(paremters));
		paremters.idle = K_DEFALUT_IDLE_TIME;
		paremters.acc_num = 1;
		paremters.accept_strategy = EN_ACCEPT_CONNS_LESS_FIRST;

		int rc = parse_listen_url(url, &paremters);
		if(rc){
			LOG_ERR("invalid url:%s", url);
			util_free_ifip(&ifips);
			return rc;
		}

		if(strcmp(paremters.sz_type, "evip") == 0){
			char* file = read_file_content("/etc/evip");
			if(NULL == file){
				printf("failed to read content from evip\n");
				return -10000;
			}

			strncpy(paremters.ip, file, sizeof(paremters.ip) - 1);
			char* last = paremters.ip+strlen(paremters.ip);
			while(last != paremters.ip){
				if(*last == '\n' || *last == '\t'){
					*last = 0;
				}
				--last;
			}

			free(file);
		}else{
			get_listen_ip(ifips, paremters.sz_ifn, paremters.ip);
		}

		if((strcmp(paremters.sz_type, "tcp") == 0 || strcmp(paremters.sz_type, "evip") == 0) && add_tcp_port(server, &paremters)){
			deallocate_String_vector(&(paremters.services));
			util_free_ifip(&ifips);
			return -2;
		}else if(strcmp(paremters.sz_type, "udp") == 0 && add_udp_port(server, &paremters)){
			util_free_ifip(&ifips);
			deallocate_String_vector(&(paremters.services));
			return -3;
		}else if(strcmp(paremters.sz_type, "http") == 0 && add_http_port(server, &paremters)){
			util_free_ifip(&ifips);
			deallocate_String_vector(&(paremters.services));
			return -4;
		}

		deallocate_String_vector(&(paremters.services));
	}

	util_free_ifip(&ifips);
	return 0;
}

#define MAX_WRITEV_NUM 20
int do_write_msg_to_tcp(void* arg)
{
	ev_ptr_t* ptr = (ev_ptr_t*)arg;
	if(NULL == ptr){
		LOG_ERR("NULL ptr, impossible!!!");
		return 0;
	}

	std::vector<struct iovec> iovs;
	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	util_get_all_rd_buff(ptr->send_chain, iovs);
    struct iovec* p_iovs;
    size_t i = 0;
    int send_len;
    size_t len = 0;

    if(iovs.size() == 0){
		LOG_ERR("impossilbe here");
		goto cancel_write;
    }
    p_iovs = (struct iovec*)calloc(iovs.size(), sizeof(struct iovec));
    for(i = 0; i < iovs.size(); ++i){
        p_iovs[i].iov_base = iovs[i].iov_base;
        p_iovs[i].iov_len = iovs[i].iov_len;
        len += iovs[i].iov_len;
    }

	send_len = writev(ptr->fd, p_iovs, iovs.size()); 
	MONITOR_ACC("sys_writev", 1);
    free(p_iovs);
	if(ptr->udp_sock){
		send_len = len;
	}

	if(send_len < 0 && (errno == EINTR || errno == EAGAIN)){
		LOG_INFO("write interrupt by :%d, host:%s:%d, totoal len:%llu", errno, ptr->ip, ptr->port, len);
		return 0;
	}else if(send_len < 0){
		LOG_ERR("write error occured:%d errno:%d err:%s, host:%s:%d", send_len, errno, strerror(errno), ptr->ip, ptr->port);
		goto cancel_write;
	}

	LOG_DBG("write %d to host:%s:%d, left len:%d", send_len, ptr->ip, ptr->port, (int)len - send_len);
	util_advance_rd(ptr->send_chain, send_len);
	if(send_len == (int)len){
		goto cancel_write;
	}

    if(send_len < (int)len){
        LOG_INFO("didn't send all buff. %llu:%d", len, send_len);
    }

	return 0;

cancel_write:
	cancel_write_ev(worker->epoll_fd, ptr);
	return 0;
}

proto_client_t* get_clients_by_service(worker_thread_t* worker, const char* service)
{
	proto_client_t* client = NULL;
	list_head* p = NULL;
	list_for_each(p, &(worker->dep_service)){
		proto_client_t* cli = list_entry(p, proto_client_t, list);
		if(strcmp(service, cli->service)){
			continue;
		}

		client = cli;
		break;
	}

	return client;
}

ev_ptr_t* get_cli_ptr_by_ip(worker_thread_t* worker, const char* service, const char* ip, int port)
{
	proto_client_t* client = get_clients_by_service(worker, service);
	if(NULL == client || NULL == ip){
		return NULL;
	}

	proto_client_inst_t* instance = NULL;
	for(size_t i = 0; i < client->num_clients; ++i){
		proto_client_inst_t* inst = client->cli_inst_s + i;
		if(strcmp(ip, inst->ip) == 0 && port == inst->port){
			instance = inst;
			break;
		}
	}

	if(NULL == instance){
		return NULL;
	}

	if(instance->ptr && !check_in_circuit_breaker(instance->ptr->breaker)){
		LOG_ERR("[%s_ALARM][%s_%s_%d]@circuit breaker failed. code:1, trace_id:0, uid:0", g_app_name, service, instance->ip, instance->port);
		if(client->breaker_setting.open){
			return NULL;
		}
	}

	return instance->ptr;
}

static ev_ptr_t* get_cli_ptr_by_round_robin(worker_thread_t* worker, coroutine_t* co, proto_client_t* client)
{
	size_t start = client->next_cli;
	if(client->hash){
		uint64_t hash_key = co->hash_key;
		if(hash_key == 0){
			hash_key = co->uctx.uid?co->uctx.uid:co->ss_req_id;
		}
		start = hash_key%(client->num_clients);//co->uid?((co->uid)%(client->num_clients)):((co->req_id)%(client->num_clients));
	}

	size_t i = start%(client->num_clients);
	do{
		client->next_cli = (client->next_cli+1)%(client->num_clients);
		proto_client_inst_t* s = client->cli_inst_s+i;
		if(s->ptr){ 
			if(check_in_circuit_breaker(s->ptr->breaker)){
				return s->ptr;
			}else{
				LOG_ERR("[%s_ALARM][%s_%s_%d]@circuit breaker failed. code:1, trace_id:0, uid:0 open:%d", g_app_name, client->service, s->ip, s->port, client->breaker_setting.open);
				if(!client->breaker_setting.open){
					return s->ptr;
				}
			}
		}

		i = (i+1)%(client->num_clients);

		if(client->hash)
			LOG_ERR("the hashed server:(%s %s:%d) is down, try to find next. worker:%llu", client->service, s->ip, s->port, (long long unsigned)worker);
	}while(i != start);

	LOG_ERR("all client of service:%s is down worker:%llu", client->service, (long long unsigned)worker);
	return NULL;
}


static ev_ptr_t* get_cli_ptr_by_weight(worker_thread_t* worker, coroutine_t* co, proto_client_t* client)
{
	list_head* list = NULL;
	list_head* p;
	list_head* n;
	proto_client_inst_t* inst;
	std::set<proto_client_inst_t*> scan_inst;
get_list:
	list = get_next_weight_cli_list(client);

	list_for_each_safe(p, n, list){
		inst = list_entry(p, proto_client_inst_t, weight_list);
		remove_client_from_weight_list(inst, client, client->weight_idx);
		put_client_inst_2_weight_list(inst, client, client->weight_idx+inst->weight);
		scan_inst.insert(inst);
#if 0
		if(inst->ptr && (check_in_circuit_breaker(inst->ptr->breaker) || !client->breaker_setting.open)){
			return inst->ptr;
		}
#endif
		if(inst->ptr){
			LOG_INFO("get cli ptr by weight. %s:%d:%d", inst->ip, inst->port, inst->weight);
			if(check_in_circuit_breaker(inst->ptr->breaker)){
				return inst->ptr;
			}else{
				LOG_ERR("[%s_ALARM][%s_%s_%d]@circuit breaker failed. code:1, trace_id:0, uid:0 open:%d", g_app_name, client->service, inst->ip, inst->port, client->breaker_setting.open);
				if(!client->breaker_setting.open){
					return inst->ptr;
				}
			}
		}
	}

	client->weight_idx = get_next_nonempty_idx(client);
	if(scan_inst.size() < client->num_clients ){
		goto get_list;
	}

	LOG_ERR("all client of service:%s is down worker:%llu", client->service, (long long unsigned)worker);
	return NULL;
}

ev_ptr_t* get_cli_ptr(worker_thread_t* worker, coroutine_t* co, const char* service)
{
	proto_client_t* client = get_clients_by_service(worker, service);
	if(NULL == client || 0 == client->num_clients){
		LOG_ERR("no client for service:%s worker:%llu", service, (long long unsigned)worker);
		return NULL;
	}

	switch(client->load_balance){
		case EN_LOAD_BALANCE_WEIGHT:
			return get_cli_ptr_by_weight(worker, co, client);
			break;
		case EN_LOAD_BALANCE_ROUND_ROBIN:
		default:
			return get_cli_ptr_by_round_robin(worker, co, client);
	}
	return NULL;
}


void monitor_accept(worker_thread_t* worker)
{
	list_head* lt = NULL;
	list_for_each(lt, &worker->listens){
		listen_t* lten = list_entry(lt, listen_t, worker);
		add_one_listen(worker, lten);
	}
}

void update_client_inst(worker_thread_t* worker, String_vector* strings)
{
	char* service = strings->data[0];
	size_t i = 0;
	int k = 0;
	std::vector<std::pair<char*,int> > ip_ports;
	char* p;
	char* ip;
	int port;
	proto_client_t* cli = NULL;
	proto_client_inst_t* cli_inst = NULL;
	list_head* ph = NULL;
	bool equal = true;

	list_for_each(ph, &(worker->dep_service)){
		proto_client_t* pc = list_entry(ph, proto_client_t, list);
		if(strcmp(service, pc->service) == 0){
			cli = pc;
			break;
		}
	}
	if(NULL == cli){
		LOG_ERR("invalid service name:%s", service);
		goto free_strings;
	}

	if(strings->count == 1){
		LOG_ERR("no service client exist, do not change. service:%s", service);
		goto free_strings;
	}

	for(k = 1; k < strings->count; ++k){
		char* ip_port = strings->data[k];
		p = ip_port;
		while(*p != 0 && *p != ':'){
			++p;
		}

		if(*p == 0 || atoi(p+1)<=0){
			LOG_ERR("invalid ip port form zk. service:%s ip_port:%s", service, ip_port);
			continue;
		}
		ip_ports.push_back(std::pair<char*, int>(strndup(ip_port, p-ip_port), atoi(p+1)));
	}

	if(ip_ports.size() == 0){
		goto free_strings;
	}

	std::sort(ip_ports.begin(), ip_ports.end(), compare_ip_port);

	//check ip port changed?
	if(cli->num_clients == ip_ports.size()){
		for(i = 0; i < ip_ports.size(); ++i){
			if(strcmp((cli->cli_inst_s+i)->ip, ip_ports[i].first) != 0 || (cli->cli_inst_s+i)->port != ip_ports[i].second){
				break;
			}
		}

		if(i != ip_ports.size()){
			equal = false;
		}
	}else{
		equal = false;
	}

	if(equal){
		LOG_DBG("recv ip:port list from zk is equal to local");
		for(i =0; i < ip_ports.size(); ++i){
			ip = ip_ports[i].first;
			free(ip);
		}
		goto free_strings;
	}

	for(i = 0; i < cli->num_clients; ++i){
		(cli->cli_inst_s+i)->invalid = 1;
	}

	cli->weight_idx = 0;
	cli->weight_bitmap = 0;

	cli_inst = (proto_client_inst_t*)calloc(ip_ports.size(), sizeof(proto_client_inst_t));
	LOG_INFO("recv ip:port list from zk, service:%s num:%llu\n", cli->service, ip_ports.size());
	for(i = 0; i < ip_ports.size(); ++i){
		ip = ip_ports[i].first;
		port = ip_ports[i].second;
		INIT_LIST_HEAD(&((cli_inst+i)->disconnected_client_wheel));
		(cli_inst+i)->req_queue_size = cli->req_queue_size;
		(cli_inst+i)->breaker_setting = &cli->breaker_setting;
		(cli_inst+i)->timeout = cli->timeout;
		(cli_inst+i)->service = cli->service;

		INIT_LIST_HEAD(&((cli_inst+i)->weight_list));
		(cli_inst+i)->weight = 1;
		put_client_inst_2_weight_list(cli_inst+i, cli, 0);

		for(k = 0; k < (int)(cli->num_clients); ++k){
			if(strcmp((cli->cli_inst_s+k)->ip, ip) == 0 && (cli->cli_inst_s+k)->port == port){
				//???del_disconnect_event_from_timer???
				list_del(&((cli->cli_inst_s+k)->disconnected_client_wheel));
				INIT_LIST_HEAD(&((cli->cli_inst_s+k)->disconnected_client_wheel));
				list_del(&((cli->cli_inst_s+k)->weight_list));
				INIT_LIST_HEAD(&((cli->cli_inst_s+k)->weight_list));
				list_del(&((cli_inst+i)->weight_list));

				memcpy(cli_inst+i, cli->cli_inst_s+k, sizeof(proto_client_inst_t));

				INIT_LIST_HEAD(&((cli_inst+i)->disconnected_client_wheel));
				INIT_LIST_HEAD(&((cli_inst+i)->weight_list));
				(cli_inst+i)->weight = (cli->cli_inst_s+k)->weight;
				put_client_inst_2_weight_list(cli_inst+i, cli, 0);

				(cli->cli_inst_s+k)->invalid = 0;
				if((cli_inst+i)->ptr){
					(cli_inst+i)->ptr->cli = (cli_inst+i);
				}else{
					LOG_DBG("add_client_inst_2_wheel worker:%llu host:%s:%d is down when recv zk ip port list", (long long unsigned)worker, (cli_inst+i)->ip, (cli_inst+i)->port);
					add_client_inst_2_wheel(worker, cli_inst+i);
				}
				break;
			}
		}

		if(k == (int)cli->num_clients){
			(cli_inst+i)->proto_type = cli->proto_type;
			(cli_inst+i)->sock_type = cli->sock_type;
			(cli_inst+i)->ssl_cert_path = cli->ssl_cert_path;
			(cli_inst+i)->ssl_cert_key = cli->ssl_cert_key;
			(cli_inst+i)->req_queue_size = cli->req_queue_size;
			(cli_inst+i)->breaker_setting = &cli->breaker_setting;
			(cli_inst+i)->timeout = cli->timeout;
			strncpy((cli_inst+i)->ip, ip, sizeof((cli_inst+i)->ip)-1);
			(cli_inst+i)->port = port;
			if(cli->sock_type == EN_SOCK_UDP){
				init_client_inst(worker, cli_inst+i, ip_ports[i], 0);
			}else{
				async_conn_server(worker, (cli_inst+i));
			}
		}

		free(ip);
	}

	for(i = 0; i < cli->num_clients; ++i){
		list_del(&((cli->cli_inst_s+i)->weight_list));
		if(!(cli->cli_inst_s+i)->invalid){
			continue;
		}

		if((cli->cli_inst_s+i)->ptr){
			LOG_ERR("client changed. worker:%llu, recycle_ev_ptr host:%s:%d fd:%d", (long long unsigned)worker,(cli->cli_inst_s+i)->ptr->ip, (cli->cli_inst_s+i)->ptr->port, (cli->cli_inst_s+i)->ptr->fd);
			//####BECAREFUL##### the order of the following line
			shut_down_ev_ptr((cli->cli_inst_s+i)->ptr);
			(cli->cli_inst_s+i)->ptr->cli = NULL;
			recycle_ev_ptr((cli->cli_inst_s+i)->ptr);
		}

		list_del(&((cli->cli_inst_s+i)->disconnected_client_wheel));
	}

	if(cli->cli_inst_s) free(cli->cli_inst_s);
	cli->cli_inst_s = cli_inst;
	cli->num_clients = ip_ports.size();
	cli->next_cli = 0;

free_strings:
	deallocate_String_vector(strings);
	free(strings);
}

void add_one_listen(worker_thread_t* worker, listen_t* lten)
{
	ev_ptr_t* ptr = get_ev_ptr(worker, lten->fd);
	ptr->do_read_ev = lten->do_epoll_ev;
	ptr->fd = lten->fd;
	ptr->arg = worker;
	ptr->listen = lten;
	lten->ptr = ptr;
	ptr->ev = 0;
	strcpy(ptr->ip, lten->ip);
	ptr->port = lten->port;
	add_read_ev(worker->epoll_fd, ptr);

	lten->accept_worker = worker;
}

static int notify_accept(worker_thread_t* next, listen_t* lt)
{
	if(NULL == lt){
		LOG_ERR("NULL listen");
		return 0;
	}

	struct cmd_t cmd;
	cmd.cmd = K_CMD_YIELD_ACCEPT;
	cmd.arg = lt;
	if(write(next->pipefd[1], &cmd, sizeof(cmd)) != sizeof(cmd)){
		LOG_ERR("failed to write accept-cmd to pipe");
		return -1;
	}

	lt->accept_worker = NULL;

	return 0;
}
