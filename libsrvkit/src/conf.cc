#include <server_inner.h>

char* g_zk_config_host = NULL;
char* g_zk_config_path = NULL;
//static char* g_zk_config_content = NULL;
extern char* g_app_name;

static json_object* read_conf_from_zk(const char* url, zk_t* zk)//char** config_host, char** config_path)
{
	if(NULL == url){
		return NULL;
	}

	char* config_host = NULL;
	char* config_path = NULL;
	parse_zk_url(url, &config_host, &config_path, NULL);
	char buffer[102400];
	buffer[0] = 0;
	int len = 102400;
	sync_get_content_from_zk(config_host, config_path, buffer, &len);

	add_config_path_2_zk(zk, config_host, config_path);
	free(config_host);
	free(config_path);

	if(len == 0){
		LOG_ERR("failed to get content from zookeeper\n");
		return NULL;
	}

	char sz_file[1024] = {0};
	snprintf(sz_file, 1023, "/tmp/.%s.cfg.json", g_app_name);

	FILE* fp = fopen(sz_file, "w");
	if(NULL == fp){
		LOG_ERR("failed to open %s", sz_file);
		return NULL;
	}

	fprintf(fp, "%s", buffer);
	fclose(fp);
	return read_conf_from_file(sz_file);
}

static json_object* load_json_cfg(zk_t* zk, const char* cfg)
{
	json_object* obj = read_conf_from_file(cfg);
	if(NULL == obj){
		return obj;
	}

	json_object* obj_zk = NULL;
	if(!json_object_object_get_ex(obj, "zk", &obj_zk)){
		return obj;
	}

	json_object* cfg_obj = read_conf_from_zk(json_object_get_string(obj_zk), zk);
	json_object_put(obj);
	if(NULL == cfg_obj){
		LOG_ERR("invalid config from zookeeper");
		return NULL;
	}

	return cfg_obj;
}

int load_cfg(server_t* server, const char* cfg)
{
	json_object* conf= load_json_cfg(&server->zk, cfg);
	if(!conf){
		return -1;
	}

	if(server->config){
		json_object_put(server->config);
	}
	server->config = conf;
	json_object_object_get_ex(server->config, "sys_conf", &server->sys_conf);
	json_object_object_get_ex(server->config, "biz_conf", &server->biz_conf);
	server->biz_conf_version = 1;
	if(server->pb_config){
		delete server->pb_config;
	}
	server->pb_config = new blink::pb_config;
	int rt = util_parse_pb_from_json(server->pb_config, server->sys_conf);
	if(rt){
		printf("######failed to parse pb from json######\n");
	}
	printf("pb config:%s\n", server->pb_config->ShortDebugString().data());

	for(int i = 0; i < server->pb_config->dep_service_size(); ++i){
		const blink::pb_dep_service& dep_service = server->pb_config->dep_service(i);
		add_dep_service_url_2_zk(&server->zk, dep_service.name().data(), dep_service.url().data());
	}

	add_regist_path_2_zk(&server->zk, server->pb_config->register_zk().data());
	return 0;
}


void get_worker_oldest_config(worker_thread_t* worker, cmd_get_oldest_biz_config_t* req)
{
	uint64_t oldest_biz_config_version = (uint64_t)-1;
	list_head* p = NULL;
	list_for_each(p, &worker->biz_config_versions){
		worker_biz_config_version_t* config = list_entry(p, worker_biz_config_version_t, list);
		if(config->cnt && config->version < oldest_biz_config_version){
			oldest_biz_config_version = config->version;
		}
	}

	req->biz_config_version = oldest_biz_config_version;
	sem_post(&req->sem);
}

void wait_worker_release_old_config(worker_thread_t* worker, uint64_t biz_conf_version)
{
	cmd_get_oldest_biz_config_t req;
	sem_init(&req.sem, 0, 0);
	req.biz_config_version = 0;
	cmd_t cmd;
	cmd.cmd = K_CMD_NOTIFY_REQ_BIZ_CONF_VERSION;
	cmd.arg = &req;

	while(1){
		int rc = notify_worker(worker, cmd);
		if(rc){
			LOG_ERR("failed to notify worker to get biz config version");
			break;
		}

		sem_wait(&req.sem);
		LOG_INFO("get biz conf version:%llu:%llu", req.biz_config_version, biz_conf_version);
		if(req.biz_config_version >= biz_conf_version){
			break;
		}
		usleep(100000);
	}

	sem_destroy(&req.sem);
	return;
}

void incr_worker_biz_config_version(worker_thread_t* worker, uint64_t biz_config_version)
{
	list_head* p = NULL;
	list_head* n = NULL;
	bool find = false;
	list_for_each_safe(p, n, &worker->biz_config_versions){
		worker_biz_config_version_t* config = list_entry(p, worker_biz_config_version_t, list);
		if(config->version == biz_config_version){
			++config->cnt;
			find = true;
		}else{
			list_del(p);
			free(config);
		}
	}

	if(find){
		return;
	}

	worker_biz_config_version_t* config = (worker_biz_config_version_t*)calloc(1, sizeof(worker_biz_config_version_t));
	config->version = biz_config_version;
	config->cnt = 1;
	INIT_LIST_HEAD(&config->list);
	list_add(&config->list, &worker->biz_config_versions);
}

void decr_worker_biz_config_version(worker_thread_t* worker, uint64_t biz_config_version)
{
	list_head* p = NULL;
	list_for_each(p, &worker->biz_config_versions){
		worker_biz_config_version_t* config = list_entry(p, worker_biz_config_version_t, list);
		if(config->version == biz_config_version){
			--config->cnt;
			return;
		}
	}
}
