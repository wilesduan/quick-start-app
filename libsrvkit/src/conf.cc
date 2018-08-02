#include <server_inner.h>

char* g_zk_config_host = NULL;
char* g_zk_config_path = NULL;
static char* g_zk_config_content = NULL;
extern char* g_app_name;

static json_object* read_conf_from_file(const char* cfg)
{
	if(NULL == cfg){
		return NULL;
	}

	char* fcontent = read_file_content(cfg);
	if(NULL == fcontent){
		return NULL;
	}

	json_object* obj = json_tokener_parse(fcontent);
	free(fcontent);
	return obj;
}

static json_object* read_conf_from_zk(const char* url)
{
	if(NULL == url){
		return NULL;
	}

	parse_zk_url(url, &g_zk_config_host, &g_zk_config_path, NULL);
	char buffer[102400];
	buffer[0] = 0;
	int len = 102400;
	sync_get_content_from_zk(g_zk_config_host, g_zk_config_path, buffer, &len);
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

	if(g_zk_config_content){
		free(g_zk_config_content);
		g_zk_config_content = NULL;
	}

	g_zk_config_content = strdup(buffer);
	return read_conf_from_file(sz_file);
}

json_object* load_cfg(const char* cfg)
{
	json_object* obj = read_conf_from_file(cfg);
	if(NULL == obj){
		return obj;
	}

	json_object* zk = NULL;
	if(!json_object_object_get_ex(obj, "zk", &zk)){
		return obj;
	}

	json_object* zk_obj = read_conf_from_zk(json_object_get_string(zk));
	json_object_put(obj);
	if(NULL == zk_obj){
		LOG_ERR("invalid config from zookeeper");
		return NULL;
	}

	return zk_obj;
}
