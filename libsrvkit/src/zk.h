#ifndef __LIBSRVKIT_ZK_H__
#define __LIBSRVKIT_ZK_H__

#include <zookeeper.h>
#include <list.h>

typedef struct dep_service_t
{
	char* path;
	char* added_group;
	char* service_name;

	char* watcherCtx[2];
	list_head list;
}dep_service_t;

inline void free_dep_service(dep_service_t* dep)
{
	if(!dep){
		return;
	}

	free(dep->path);
	free(dep->added_group);
	free(dep->service_name);
	free(dep);
}

typedef struct regist_t
{
	char* path;
	char* group;
	list_head list;
}regist_t;

inline void free_regist(regist_t* reg)
{
	if(!reg){
		return;
	}

	free(reg->path);
	free(reg->group);
	free(reg);
}

struct server_t;
typedef struct zk_inst_t
{
	server_t* server;
	pthread_t zk_thread;
	//char* watcherCtx[2];

	zhandle_t* zkhandle;
	pthread_mutex_t zk_mutex;

	char* host;
	char* config_path;

	list_head reg_list;
	list_head dep_list;

	list_head list;
}zk_inst_t;

inline void free_zk_inst(zk_inst_t* inst)
{
	if(!inst){
		return;
	}

	free(inst->host);
	free(inst->config_path);

	list_head *pr, *nr;
	list_for_each_safe(pr, nr, &inst->reg_list){
		regist_t* reg = list_entry(pr, regist_t, list);
		list_del(pr);
		free_regist(reg);
	}

	list_head *pd, *nd;
	list_for_each_safe(pd, nd, &inst->dep_list){
		dep_service_t* d = list_entry(pd, dep_service_t, list);
		list_del(pd);
		free_dep_service(d);
	}

	free(inst);
}

typedef struct zk_t
{
	list_head zk_insts;
}zk_t;

void init_zk(zk_t* zk);
void release_zk(zk_t* zk);
int add_config_path_2_zk(zk_t* zk, const char* host, const char* config_path);
int add_regist_path_2_zk(zk_t* zk, const char* url);
int add_dep_service_url_2_zk(zk_t* zk, const char* name, const char* url);

void run_zk_threads(server_t* server);
void stop_zk_threads(server_t* server);//sleep 10

void sync_get_content_from_zk(const char* host, const char* path, char* buffer, int* len);
void get_ip_port_from_zk(const char* url, std::vector<std::pair<char*, int> >& ip_ports);
bool compare_ip_port(const std::pair<char*, int>& p1, const std::pair<char*, int>& p2);
#endif//__LIBSRVKIT_ZK_H__

