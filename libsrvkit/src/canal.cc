#include <canal.h>
#include <canal.pb.h>
#define K_CANAL_CONSUMER "canal_consumer"

const char* get_canal_method(worker_thread_t* worker, const char* database, const char* table, const char* type)
{
	server_t* server = (server_t*)(worker->mt);
	list_head* ls = NULL;
	list_for_each(ls, &(server->services)){
		service_t* svc = list_entry(ls, service_t, list);
		if(strcmp(svc->name, K_CANAL_CONSUMER)){
			continue;
		}

		for(int i = 0; i < svc->num_methods; ++i){
			if(strcmp(svc->swoole_meth[i].database, database) == 0 
			   && (svc->swoole_meth[i].table?(strcmp(svc->swoole_meth[i].table, table) == 0):1) 
			   && strcmp(svc->swoole_meth[i].type, type) == 0){
				return svc->swoole_meth[i].method_name;
			}
		}

		return NULL;
	}

	return NULL;
	//TODO
	return NULL;
}

int process_canal_request(ev_ptr_t* ptr, json_object* obj)
{
	json_object* js_db = NULL;
	json_object* js_table = NULL;
	json_object* js_type = NULL;
	json_object* js_data = NULL;
	json_object* js_old = NULL;
	json_object_object_get_ex(obj, "database", &js_db);
	json_object_object_get_ex(obj, "table", &js_table);
	json_object_object_get_ex(obj, "type", &js_type);
	json_object_object_get_ex(obj, "data", &js_data);
	json_object_object_get_ex(obj, "old", &js_old);

	if(!js_data){
		LOG_ERR("miss data");
		return 0;
	}

	const char* database = js_db?json_object_get_string(js_db):NULL;
	const char* table = js_table?json_object_get_string(js_table):NULL;
	const char* type = js_type?json_object_get_string(js_type):NULL;

	worker_thread_t* worker = (worker_thread_t*)(ptr->arg);
	const char* method = get_canal_method(worker, database, table, type);
	if(!method){
		LOG_ERR("failed to get method name for:%s:%s:%s", database?database:"NULL", table?table:"NULL", type?type:"NULL");
		return 0;
	}

	swoole_head_t head;
	snprintf(head.cmd, sizeof(head.cmd), "0%s.%s", K_CANAL_CONSUMER, method);
	//construct swoole request 
	json_object* js_header = json_object_new_object();
	json_object_object_add(js_header, "caller", json_object_new_string("canal"));

	json_object* js_body = json_object_new_object();
	json_object* js_rows = json_object_new_array();
	for(int i = 0; i < json_object_array_length(js_data); ++i){
		json_object* js_new_value = json_object_get(json_object_array_get_idx(js_data, i));
		json_object* js_old_value = js_old?json_object_get(json_object_array_get_idx(js_old, i)):NULL;

		json_object* js_row = json_object_new_object();
		json_object_object_add(js_row, "new", js_new_value);
		if(js_old_value){
			json_object_object_add(js_row, "old", js_old_value);
		}

		json_object_array_add(js_rows, js_row);
	}
	json_object_object_add(js_body, "rows", js_rows);

	json_object* js_swoole = json_object_new_object();
	json_object_object_add(js_swoole, "header", js_header);
	json_object_object_add(js_swoole, "body", js_body);

	int rc = process_swoole_request(ptr, &head, json_object_to_json_string(js_swoole));
	json_object_put(js_swoole);
	return rc;
}
