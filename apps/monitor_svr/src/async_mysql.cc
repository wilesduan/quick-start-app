#include <async_mysql.h>
#include <async_task.h>
#define MONITOR_INTERVAL_TIME 60

static async_routine_t* g_async_mysql_routine = NULL;
static worker_thread_t dummy_worker;

int init_async_mysql_module(server_t* server)
{
	json_object* js_config = server->config;
	json_object* js_mysql;
	json_object_object_get_ex(js_config, "mysql", &js_mysql);
	if(!js_mysql){
		LOG_ERR("miss mysql config");
		return -10;
	}

	int rc = connect_2_mysql(&dummy_worker, js_mysql);
	if(rc){
		LOG_ERR("failed to connect 2 mysql");
		return -11;
	}

	g_async_mysql_routine = malloc_async_routines(1, 1000);
	if(!g_async_mysql_routine){
		LOG_ERR("failed to create mysql async routine");
		return -12;
	}

	run_async_routines(g_async_mysql_routine, 1);
	return 0;
}

static int fn_write_monitor_log(void* arg)
{
	blink::ReqAddMonitorLog* logs = (blink::ReqAddMonitorLog*)arg;
	static time_t last_store_time = time(NULL);
	static std::map<std::string, std::map<std::string, int64_t> > monitor_logs;

	//=======================begin save logs 2 map===========================//
    int size = logs->monitor_log_size();
	for(int i = 0; i < size; ++i){
        const blink::MonitorDataInner& t_data = logs->monitor_log(i);
        const std::string& service_type = t_data.service_type();
        const std::string& monitor_key = t_data.monitor_key();
        int64_t monitor_value = t_data.monitor_value();

		std::map<std::string , std::map<std::string ,int64_t> >::iterator it_service = monitor_logs.find(service_type);  
		if(it_service == monitor_logs.end()){
			std::map<std::string ,int64_t> tmp_map;
			tmp_map.insert(std::pair<std::string,int64_t>(monitor_key,monitor_value));
			monitor_logs.insert(make_pair(service_type,tmp_map));
			continue;
		}

        std::map<std::string,int64_t>:: iterator it_key = it_service->second.find(monitor_key);
		if(it_key == it_service->second.end()){
            it_service->second.insert(std::pair<std::string,int64_t>(monitor_key,monitor_value));
			continue;
		}

		if(strstr(monitor_key.data(), "_max_")){
			it_key->second = it_key->second > monitor_value?it_key->second:monitor_value;
		}else{
			it_key->second += monitor_value;
		}
	}
	delete logs;
	//=======================end save logs 2 map===========================//

	//======================begin flush logs 2 mysql======================//
	time_t now = time(NULL);
	if(abs(now - last_store_time) < MONITOR_INTERVAL_TIME){
		return 0;
	}
	last_store_time = now;
	rpc_ctx_t ctx;
	ev_ptr_t ptr;
	ptr.arg = &dummy_worker;
	ctx.ptr = &ptr;

	coroutine_t co;
	bzero(&co, sizeof(coroutine_t));
	co.worker = &dummy_worker;
	ctx.co = &co;
    MYSQL* mysql = get_mysql_from_rpc(&ctx, 0);
    if(mysql == NULL){
        LOG_ERR("[MONITOR_ALARM][connect_error]@mysql get error, server: monitor, error: connect error");
		return 0;
	}
    std::string tmpl_query = "INSERT INTO t_monitor (service_type,monitor_key,monitor_value) values ";
    std::map<std::string , std::map<std::string ,int64_t> >::iterator iter_service;
    std::map<std::string ,int64_t> ::iterator iter_key;
	char insert_query[102400];
	int len = snprintf(insert_query, sizeof(insert_query), "%s", tmpl_query.data());
	int values = 0;
	for(iter_service = monitor_logs.begin(); iter_service != monitor_logs.end(); ++iter_service){
		const std::string& service = iter_service->first;
		int cnt = 0;
		int total = iter_service->second.size();
		for(iter_key = iter_service->second.begin(); iter_key != iter_service->second.end(); ++iter_key){
			++cnt;
			const std::string& key = iter_key->first;
			int64_t monitor_value = iter_key->second;
			if(values){
				len+= snprintf(insert_query+len, sizeof(insert_query)-len, ",");
			}
			len += snprintf(insert_query+len, sizeof(insert_query)-len, "(\"%s\", \"%s\", %" PRIu64 ")", service.data(), key.data(), monitor_value);
			++values;

			if(values < 100 && cnt < total){
				continue;
			}

			insert_query[len++] = ';';
			insert_query[len] = 0;
            mysql_query_t* query = mysql_malloc_query(&ctx, mysql, insert_query);
			query->async = 0;
            int rc = execute_mysql_query(query);
			if(rc){
                LOG_ERR("[MONITOR_ALARM][excute_error]@failed to execute query:%d:%s\n", rc, query->reslt.mysql_errmsg);
			}

            mysql_free_query(query);
			values = 0;
			len = snprintf(insert_query, sizeof(insert_query), "%s", tmpl_query.data());
		}
	}

	monitor_logs.clear();
	//======================end flush logs 2 mysql======================//

	return 0;
}

int add_log_2_mysql(const blink::ReqAddMonitorLog* req)
{
	if(!g_async_mysql_routine){
		LOG_ERR("no mysql routine");
		return 0;
	}

	blink::ReqAddMonitorLog* logs = new blink::ReqAddMonitorLog();
	logs->CopyFrom(*req);
	add_task_2_routine(g_async_mysql_routine, fn_write_monitor_log, logs, 1);
	return 0;
}
