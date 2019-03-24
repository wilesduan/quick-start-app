#include <server_inner.h>
#include <sys/syscall.h>  
#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper.jute.h>
#include <zk_adaptor.h>

#define gettid() syscall(__NR_gettid)  
#define K_SERVICE_GROUP "/etc/machine_group"
#define K_DEFALUT_GROUP "default"

extern char g_ip[24];
extern char* g_zk_config_host;
extern char* g_zk_config_path;
extern char g_start_time[128];
extern char* g_app_name;
extern int g_exit_status;

pthread_mutex_t zk_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_stop_zk_thread = 0;

static char* get_first_line_content(char* content);
static void zk_state_watcher(zhandle_t* zkhandle, int type, int state, const char* path, void* ctx);

static void sync_config_from_zk(server_t* server)
{
	if(!g_zk_config_path){
		return;
	}

	int daemon = server->pb_config->daemon(); 
	if(!daemon){
		return;
	}

	char buffer[102400];
	buffer[0] = 0;
	int len = 102400-1;

	int rc = zoo_get(server->zkhandle, g_zk_config_path, 0, buffer, &len, NULL);
	if(rc != ZOK){
		return;
	}

	buffer[len] = 0;

	json_object* js_cfg = json_tokener_parse(buffer);
	if(!js_cfg){
		return;
	}

	json_object* obj = NULL;
	json_object_object_get_ex(js_cfg, "auto_load", &obj);
	int auto_load = obj?json_object_get_int(obj):0;
	if(!auto_load){
		json_object_put(js_cfg);
		return;
	}

	//1. compare cfg with old config
	if(server->config &&  util_json_object_equal(server->config, js_cfg)){
		json_object_put(js_cfg);
		return;
	}

	json_object_put(js_cfg);

	//2. get zk lock
	while(1){
		// /libsrvkit/autoload/service
		zoo_create(server->zkhandle, "/libsrvkit", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
		zoo_create(server->zkhandle, "/libsrvkit/autoload", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
		zoo_create(server->zkhandle, "/libsrvkit/autoload/", "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
		char tmp[256];
		snprintf(tmp, 256, "/libsrvkit/autoload/%s", g_app_name);
		int rc = zoo_create(server->zkhandle, tmp, g_ip, strlen(g_ip), &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);
		if(rc != ZOK){
			return;
		}
		break;
	}

	g_exit_status = K_EXIT_BY_CONF_CHG;
	server->exit = 1;
	g_stop_zk_thread = 1;
	LOG_INFO("recv new config, process will restart soon");
}

#define K_MAX_ZK_PATH_LEN 1024
#define K_MAX_SERVICE_GROUP_LEN 128
static void get_register_path_group(server_t* server, char* path, char* group)
{
	static char sz_path[K_MAX_ZK_PATH_LEN] = {0};
	static char sz_group[K_MAX_SERVICE_GROUP_LEN] = {0};
	static bool parsed = false;
	if(parsed){
		strcpy(path, sz_path);
		strcpy(group, sz_group);
		return;
	}

	parsed = true;
	if(!server->pb_config->register_zk().size()){
		return;
	}

	const char* zk_url = server->pb_config->register_zk().data(); 
	char* c_path = NULL;
	parse_zk_url(zk_url, NULL, &c_path, NULL);
	if(NULL == c_path){
		return;
	}

	snprintf(sz_path, sizeof(sz_path)-1, "%s", c_path);
	free(c_path);

	char* content = read_file_content(K_SERVICE_GROUP);
	const char* c_group = content?get_first_line_content(content):K_DEFALUT_GROUP;
	strncpy(sz_group, c_group, K_MAX_SERVICE_GROUP_LEN-1);

	if(content)
		free(content);

	strcpy(path, sz_path);
	strcpy(group, sz_group);
}

//这个名字太傻
static int register_srv_to_zk(server_t* server, int regist)
{
	if(!server->zkhandle){
		LOG_ERR("zookeeper handle is null");
		return 0;
	}

	char path[1024] = {0};
	char group[128] = {0};
	get_register_path_group(server, path, group);
	size_t len = strlen(path);
	if(len == 0){
		return 0;
	}

	/*************************loop create************************************/
	int part = 0;
	char* p = path+1;
	while(*p != 0){
		if(*p == '/') ++part;
		++p;
	}

	if(*(p-1) != '/') ++part;
	if(*(p-1) == '/' && path[0] !='/') --part;
	part += 2;

	String_vector path_vector;
	path_vector.count = part;
	path_vector.data = (char**)calloc(part, sizeof(char*));

	p = path+1;
	int n = 0;
	while(*p != 0){
		if(*p == '/'){
			*p = 0;
			path_vector.data[n] = strdup(path);
			//zoo_create_op_init(ops+n, path_vector.data[n], "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
			++n;
			*p = '/';
		}
		++p;
	}
	path_vector.data[part-3] = strdup(path);
	//zoo_create_op_init(ops+part-3, path_vector.data[part-3], "", 0, &ZOO_OPEN_ACL_UNSAFE, 0 , NULL, 0);
	/**************************end loop****************************************/

	char js_group[1024];
	snprintf(js_group, sizeof(js_group),"{\"group\":\"%s\", \"startup_time\":\"%s\"}", group, g_start_time);
	
	list_head* lt = NULL;
	char ip[24];
	list_for_each(lt, &(server->listens)){
		listen_t* lit = list_entry(lt, listen_t, list);
		if(strcmp(lit->ip, "0.0.0.0") == 0){
			struct sockaddr_in addr;
			socklen_t addr_len = sizeof(addr);
			getsockname(server->zkhandle->fd, (sockaddr*)&addr, &addr_len);
			inet_ntop(AF_INET, &(addr.sin_addr), ip, sizeof(ip));

			bool valid_ip = false;
			ifip_t* ifips = util_get_local_ifip();
			ifip_t* oifips = ifips;
			while(ifips){
				if(strcmp(ip, ifips->ip) == 0){
					valid_ip = true;
					break;
				}

				ifips = ifips->next;
			}
			util_free_ifip(&oifips);

			if(!valid_ip){
				LOG_ERR("failed to get loal ip");
				continue;//register next
			}

		}else{
			strcpy(ip, lit->ip);
		}

		for(int i = 0; i < lit->count; ++i){
			char* service = lit->lt_services[i];
			char* last_char = path+len-1;
			if(*last_char == '/'){
				int app_len = snprintf(path+len, sizeof(path)-len-1, "%s", service);
				if(path_vector.data[part-2]){
					free(path_vector.data[part-2]);
				}
				path_vector.data[part-2] = strdup(path);
				snprintf(path+len+app_len, sizeof(path)-len-1-app_len, "/%s:%d", ip, lit->port);
			}else{
				int app_len = snprintf(path+len, sizeof(path)-len-1, "/%s", service);
				if(path_vector.data[part-2]){
					free(path_vector.data[part-2]);
				}
				path_vector.data[part-2] = strdup(path);
				snprintf(path+len+app_len, sizeof(path)-len-1-app_len, "/%s:%d", ip, lit->port);
			}

			if(path_vector.data[part-1]){
				free(path_vector.data[part-1]);
			}
			path_vector.data[part-1] = strdup(path);
			for(int i = 0; i < part-1; ++i){
				zoo_create(server->zkhandle, path_vector.data[i], "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
			}

			if(regist){
				zoo_create(server->zkhandle, path_vector.data[part-1], js_group, strlen(js_group), &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);
			}else{
				zoo_delete(server->zkhandle, path_vector.data[part-1], -1);
			}
		}
	}

	deallocate_String_vector(&path_vector);
	strncpy(g_ip, ip, sizeof(g_ip));
	return 0;
}

static void fn_get_zknode_children(int rc, const struct String_vector* strings, const void* data);
static void fn_watch_zknode_children(zhandle_t* zkhandle, int type, int state, const char* path, void* watcherCtx)
{
	printf("fn_watch_zknode_children in thread:%ld\n", gettid());
	if(state == ZOO_CONNECTED_STATE){
		pthread_mutex_lock(&zk_mutex);
		LOG_INFO("zk event path:%s type:%d", path, type);
		server_t* server = (server_t*)(((char**)watcherCtx)[0]);
		if(server && server->zkhandle){
			zoo_awget_children(server->zkhandle, path, fn_watch_zknode_children, watcherCtx, fn_get_zknode_children, watcherCtx);
		}else{
			LOG_ERR("zk is down");
		}

		pthread_mutex_unlock(&zk_mutex);
	}
}

static bool check_is_added_group(const char* group, const char* added_group)
{
	if(!group || !added_group) return false;
	const char* p = added_group;
	while(p && (p = strstr(p, group))) {
		p += strlen(group);
		if(*p == ',' || !*p)
			return true;
		p = strchr(p, ',');
	}
	return false;
}

static void get_same_group_node(zhandle_t* zkhandle, const char* zk_path, const String_vector* childrens, String_vector* group_vector, char* added_group)
{
	char* content = read_file_content(K_SERVICE_GROUP);
	const char* c_group = content?get_first_line_content(content):K_DEFALUT_GROUP;

	memset(group_vector, 0, sizeof(String_vector));
	group_vector->count = 0;
	group_vector->data = (char**)calloc(childrens->count, sizeof(char*));
	String_vector added_group_vector;
	memset(&added_group_vector, 0, sizeof(String_vector));
	added_group_vector.count = 0;
	added_group_vector.data = (char**)calloc(childrens->count, sizeof(char*));
	char sz_child_path[1024];
	char sz_content[1024];
	for(int i = 0; i < childrens->count; ++i){
		snprintf(sz_child_path, sizeof(sz_child_path), "%s/%s", zk_path, childrens->data[i]);

		memset(sz_content, 0, sizeof(sz_content));
		int len = sizeof(sz_content)-1;
		int rc = zoo_get(zkhandle, sz_child_path, 0, sz_content, &len, NULL);
		if(rc != ZOK){
			LOG_ERR("failed to fetch zk path:%s", sz_child_path);
			continue;
		}

		json_object* obj = json_tokener_parse(sz_content);
		if(NULL == obj){
			LOG_ERR("failed to parse content:%s from path:%s", sz_content, sz_child_path);
			continue;
		}

		json_object* js_group = NULL;
		if(!json_object_object_get_ex(obj, "group", &js_group)){
			json_object_put(obj);
			LOG_ERR("no group in path:%s content:%s", sz_child_path, sz_content);
			continue;
		}

		const char* g = json_object_get_string(js_group);
		if(strcmp(g, c_group) == 0){
			group_vector->data[(group_vector->count)++] = childrens->data[i];
		}
		if(!group_vector->count && added_group) {
			if(check_is_added_group(g, added_group)) {
				added_group_vector.data[(added_group_vector.count)++] = childrens->data[i];
			}
		}
		json_object_put(obj);
	}
	if(!group_vector->count && added_group_vector.count) {
		for(int i = 0; i < added_group_vector.count; ++i){
			group_vector->data[(group_vector->count)++] = added_group_vector.data[i];
		}
	}
	free(added_group_vector.data);

	if(content) free(content);
}

static void update_dep_service(server_t* server, proto_client_t* cli, const struct String_vector* dep_service)
{
	if(NULL == cli || NULL == dep_service || dep_service->count == 0){
		return;
	}

	char* zk_path = NULL;
	char* added_group = NULL;
	parse_zk_url(cli->url, NULL, &zk_path, &added_group);
	String_vector group_vector;
	memset(&group_vector, 0, sizeof(group_vector));
	if(zk_path){
		get_same_group_node(server->zkhandle, zk_path, dep_service, &group_vector, added_group);
	}
	if(zk_path) free(zk_path);
	if(added_group) free(added_group);

	const String_vector* p_service = group_vector.count>0?&group_vector:dep_service;
	for(int i = 0; i < server->num_worker; ++i){
		worker_thread_t* worker = server->array_worker+i;
		String_vector* strings = (String_vector*)calloc(1, sizeof(String_vector));
		strings->count = p_service->count+1;
		strings->data = (char**)calloc(strings->count, sizeof(char*));
		strings->data[0] = strdup(cli->service);
		for(int j = 0; j < p_service->count; ++j){
			strings->data[j+1] = strdup(p_service->data[j]);
		}

		cmd_t cmd;
		cmd.cmd = K_CMD_NOTIFY_DEP_SERVICE;
		cmd.arg = strings;
		if(write(worker->pipefd[1], &cmd, sizeof(cmd)) != sizeof(cmd)){
			deallocate_String_vector(strings);
			free(strings);
		}
	}

	if(group_vector.data){
		free(group_vector.data);
	}

}

static void fn_get_zknode_children(int rc, const struct String_vector* strings, const void* data)
{
	if(rc != ZOK){
		return;
	}


	char** watcherCtx = (char**)data;
	update_dep_service((server_t*)watcherCtx[0], (proto_client_t*)watcherCtx[1], strings);
}

static int do_zk_dep_service(server_t* server, bool sync)
{
	if(NULL == server->zkhandle || server->num_worker <= 0){
		return 0;
	}

	char* zk_path = NULL;
	worker_thread_t* worker = server->array_worker;
	list_head* dep = NULL;
	list_for_each(dep, &(worker->dep_service)){
		proto_client_t* cli = list_entry(dep, proto_client_t, list);
		if(!cli->from_zk){
			continue;
		}

		parse_zk_url(cli->url, NULL, &zk_path, NULL);
		if(NULL == zk_path){
			LOG_ERR("invalid zk url:%s", cli->url);;
			continue;
		}

		size_t path_len = strlen(zk_path);
		if(path_len == 0 || path_len >= K_MAX_ZK_PATH_LEN - K_MAX_SERVICE_GROUP_LEN){
			free(zk_path);
			continue;
		}

		if(sync){
			String_vector dep_services;
			memset(&dep_services, 0, sizeof(String_vector));
			int rc = zoo_get_children(server->zkhandle, zk_path, 0, &dep_services);
			if(rc == ZOK){
				update_dep_service(server, cli, &dep_services);
			}
			deallocate_String_vector(&dep_services);
		}else{
			cli->watcherCtx[0] = (char*)server;
			cli->watcherCtx[1] = (char*)cli;
			int rc = zoo_awget_children(server->zkhandle, zk_path, fn_watch_zknode_children, cli->watcherCtx, fn_get_zknode_children, cli->watcherCtx);
			if(rc != ZOK){
				LOG_ERR("failed to awget children");
			}
		}

		free(zk_path);
		zk_path = NULL;
	}

	return 0;
}

static int sync_zk_dep_service(server_t* server)
{
	return do_zk_dep_service(server, 1);
}

static int async_zk_dep_service(server_t* server)
{
	return do_zk_dep_service(server, 0);
}

bool should_connect_2_zk(server_t* server)
{
	if(g_zk_config_host){
		free(g_zk_config_host);
		g_zk_config_host = NULL;
	}

	if(server->num_worker <= 0){
		return false;
	}

	worker_thread_t* worker = server->array_worker;
	list_head* dep = NULL;
	list_for_each(dep, &(worker->dep_service)){
		proto_client_t* cli = list_entry(dep, proto_client_t, list);
		if(cli->from_zk){
			parse_zk_url(cli->url, &g_zk_config_host, NULL, NULL);
			LOG_INFO("zk host:%s", g_zk_config_host);
			return true;
		}
	}

	if(!server->pb_config->register_zk().size()){ 
		return false;
	}

	const char* zk_url = server->pb_config->register_zk().data();
	parse_zk_url(zk_url, &g_zk_config_host, NULL, NULL);
	if(NULL == g_zk_config_host){
		return false;
	}

	LOG_INFO("zk host:%s", g_zk_config_host);
	return true;
}

static void connect_zk(server_t* server)
{
	do{
		server->zkhandle = zookeeper_init(g_zk_config_host, zk_state_watcher, 3000, 0, server, 0);
		if(NULL != server->zkhandle){
			break;
		}

		sleep(1);
	}while(NULL == server->zkhandle);
}

static void zk_state_watcher(zhandle_t* zkhandle, int type, int state, const char* path, void* ctx)
{
	printf("zk_state_watcher in thread:%ld\n", gettid());
	if(type == ZOO_SESSION_EVENT){
		if(state == ZOO_CONNECTED_STATE){
			LOG_INFO("zookeeper connected");
			return;
		}else if(state == ZOO_EXPIRED_SESSION_STATE){
			server_t* server = (server_t*)ctx;

			pthread_mutex_lock(&zk_mutex);
			server->zkhandle = NULL;
			zookeeper_close(zkhandle);
			connect_zk(server);
			async_zk_dep_service(server);
			pthread_mutex_unlock(&zk_mutex);
		}
	}
}

void* run_zk_thread(void* arg)
{
	server_t* server = (server_t*)arg;

	connect_zk(server);
	async_zk_dep_service(server);

	//int i = 0;
	while(!g_stop_zk_thread){
		printf("run_zk_thread in thread:%ld\n", gettid());
		pthread_mutex_lock(&zk_mutex);
		if(server->zkhandle){
			register_srv_to_zk(server, 1);
			sync_zk_dep_service(server);
			sync_config_from_zk(server);
		}
		pthread_mutex_unlock(&zk_mutex);
		sleep(5);
	}

	LOG_INFO("unregister zk");
	register_srv_to_zk(server, 0);
	return NULL;
}

static void sync_connect_zk_watcher(zhandle_t* zkhandler, int type, int stat, const char* path, void* ctx)
{
	if(type == ZOO_SESSION_EVENT){
		if(stat == ZOO_CONNECTED_STATE){
			LOG_INFO("sync connect zookeeper successfully!\n");
		}else {
			LOG_INFO("sync connect zookeeper stat not connected!\n");
			zookeeper_close(zkhandler);
		}
	}
}

static zhandle_t*  sync_connect_zk(const char* host)
{
	zhandle_t* zkhandle = zookeeper_init(host, sync_connect_zk_watcher, 3000, 0, NULL, 0);
	if(NULL == zkhandle){
		LOG_ERR("failed to connect to zk:%s", host);
		return NULL;
	}

	int i = 0;
	while(i < 5 && zoo_state(zkhandle) != ZOO_CONNECTED_STATE){
		usleep(10000);
		++i;
	}

	if(i == 5){
		LOG_ERR("failed to connect to zk:%s", host);
		zookeeper_close(zkhandle);
		return NULL;
	}

	return zkhandle;
}

static void sync_get_service_node_from_zk(const char* host, const char* path, char* added_group, String_vector* strings, String_vector* group_vector)
{
	if(NULL == strings){
		return;
	}

	zhandle_t* zkhandle = sync_connect_zk(host);
	if(NULL == zkhandle){
		return;
	}

	int rc = zoo_get_children(zkhandle, path, 0, strings);
	if(rc != ZOK){
		LOG_ERR("failed to get children from zookeeper. path:%s", path);
	}

	get_same_group_node(zkhandle, path, strings, group_vector, added_group);
	zookeeper_close(zkhandle);
}

void sync_get_content_from_zk(const char* host, const char* path, char* buffer, int* len)
{
	zhandle_t* zkhandle = sync_connect_zk(host);
	if(NULL == zkhandle){
		LOG_ERR("failed to connect to zk:%s", host);
		*len = 0;
		return;
	}

	
	int rc = zoo_get(zkhandle, path, 0, buffer, len, NULL);
	if(rc != ZOK){
		LOG_ERR("failed to get content from zookeeper\n");
		*len = 0;
		zookeeper_close(zkhandle);
		return;
	}
	buffer[*len] = 0;
	zookeeper_close(zkhandle);
}

static char* get_first_line_content(char* content)
{
	char* p = content;
	while(*p == 0 && (*p == ' '|| *p == '\t' || *p == '\n')){
		++p;
	}

	if(*p == 0)
		return NULL;

	char* end = p;
	while(*end != 0 && *end != ' ' && *end != '\t' && *end != '\n'){
		++end;
	}

	*end = 0;
	return p;
}

bool compare_ip_port(const std::pair<char*, int>& p1, const std::pair<char*, int>& p2)
{
	int cmp = strcmp(p1.first, p2.first);
	if(cmp != 0){
		return cmp > 0;
	}

	return p1.second > p2.second;
}

void get_ip_port_from_zk(const char* url, std::vector<std::pair<char*, int> >& ip_ports)
{
	char* host = NULL;
	char* path = NULL;
	char* added_group = NULL;

	parse_zk_url(url, &host, &path, &added_group);
	if(NULL == host || NULL == path){
		return;
	}

	String_vector clients;
	String_vector group_vector;
	memset(&clients, 0, sizeof(String_vector));
	memset(&group_vector, 0, sizeof(String_vector));
	sync_get_service_node_from_zk(host, path, added_group, &clients, &group_vector);
	free(host);
	free(path);
	if(added_group) free(added_group);
	if(clients.count == 0){
		if(group_vector.data){
			free(group_vector.data);
		}

		deallocate_String_vector(&clients);
		return;
	}

	String_vector* p_service = group_vector.count>0?&group_vector:&clients;
	for(int i = 0; i < p_service->count; ++i){
		char* ip_port = p_service->data[i];
		char* ip = NULL;
		int port = 0;
		char* p = NULL;
		if(NULL == ip_port){
			continue;
		}
		p = ip_port;
		while(*p != 0 && *p != ':'){
			++p;
		}

		if(*p == 0){
			continue;
		}

		port = atoi(p+1);
		if(port <= 0){
			continue;
		}

		ip = strndup(ip_port, p-ip_port);
		ip_ports.push_back(std::pair<char*, int>(ip, port));
	}

	std::sort(ip_ports.begin(), ip_ports.end(), compare_ip_port);
	deallocate_String_vector(&clients);
	if(group_vector.data){
		free(group_vector.data);
	}
}

