#include <mysql_wrapper.h>
#include <json.h>
#include <bim_util.h>
#include <sys/time.h> 
//#include <sql_common.h>
#include <server_inner.h>

static const char* msg_mysql_stucked = "[ALARM MYSQL too slow]";

static int cmp_mysql_inst(mysql_conn_inst_t* mysql_conn, const char* host, int port, const char* user, const char* password)
{
	int rt = strcmp(mysql_conn->host, host);
	if(rt){
		return rt;
	}

	if(mysql_conn->port != port){
		return mysql_conn->port - port;
	}

	rt = strcmp(mysql_conn->user, user);
	if(rt){
		return rt;
	}

	rt = strcmp(mysql_conn->password, password);
	if(rt){
		return rt;
	}

	return 0;
}

static mysql_conn_inst_t* get_mysql_conn_inst(mysql_wrapper_t* wrapper, const char* host, int port, const char* user, const char* password, int max_pending_query)
{
	struct rb_node** node = &(wrapper->conn_insts.rb_node), *parent = NULL;
	while(*node){
		mysql_conn_inst_t* mysql_conn = rb_entry(*node, mysql_conn_inst_t, node); 
		parent = *node;
		int cmp = cmp_mysql_inst(mysql_conn, host, port, user, password);
		if(cmp == 0){
			return mysql_conn;
		}else if(cmp > 0){
			node = &((*node)->rb_left);
		}else{
			node = &((*node)->rb_right);
		}
	}

	mysql_conn_inst_t* mysql_conn = (mysql_conn_inst_t*)calloc(1, sizeof(mysql_conn_inst_t));
	mysql_conn->host = strdup(host);
	mysql_conn->port = port;
	mysql_conn->user = strdup(user);
	mysql_conn->password = strdup(password);
	mysql_conn->max_pending_query = max_pending_query;

	mysql_conn->asyncer= malloc_async_routines(1, mysql_conn->max_pending_query);
	run_async_routines((async_routine_t*)(mysql_conn->asyncer), 1);

	int	rc = connect_2_mysql_inst(mysql_conn);
	if(rc){
		LOG_INFO("FAILED connect to mysql:%s:%d %s:%s", host, port, user, password);
#if 0
		free(mysql_conn->host);
		free(mysql_conn->user);
		free(mysql_conn->password);
		free(mysql_conn);
		return NULL;
		*/
#endif
	}else{
		LOG_INFO("connect to mysql:%s:%d %s:%s", host, port, user, password);
	}

	rb_link_node(&(mysql_conn->node), parent, node); 
	rb_insert_color(&(mysql_conn->node), &(wrapper->conn_insts));
	return mysql_conn;
}

//static int parse_mysql_url(const char* url, mysql_inst_t* inst);
int init_wrapper_with_config(mysql_wrapper_t* wrapper, json_object* conf)
{
	wrapper->type = EN_MYSQL_WRAPPER_TYPE_SHARD;
	json_object* js_type = NULL;
	if(json_object_object_get_ex(conf, "type", &js_type)){
		const char* type = json_object_get_string(js_type);
		if(strcmp(type, "fabric") == 0){
			wrapper->type = EN_MYSQL_WRAPPER_TYPE_FABRIC;
		}
	}

	json_object* js_hosts = NULL;
	if(!json_object_object_get_ex(conf, "hosts", &js_hosts)){
		LOG_ERR("no mysql hosts in config");
		return 0;
	}

	wrapper->num_instances = json_object_array_length(js_hosts);
	if(0 == wrapper->num_instances){
		LOG_ERR("no mysql hosts in config");
		return 0;
	}

	int has_failed = 0;
	wrapper->instances = (mysql_inst_t*)calloc(wrapper->num_instances, sizeof(mysql_inst_t));
	for(size_t i = 0; i < wrapper->num_instances; ++i){
		json_object* js_host = json_object_array_get_idx(js_hosts, i);

		json_object* js_id = NULL;
		json_object_object_get_ex(js_host, "id", &js_id);

		json_object* js_user = NULL;
		json_object_object_get_ex(js_host, "user", &js_user);

		json_object* js_passwd = NULL;
		json_object_object_get_ex(js_host, "passwd", &js_passwd);

		json_object* js_ip = NULL;
		json_object_object_get_ex(js_host, "ip", &js_ip);

		json_object* js_port = NULL;
		json_object_object_get_ex(js_host, "port", &js_port);
		
		json_object* js_charset = NULL;
		json_object_object_get_ex(js_host, "charset", &js_charset);

		json_object* js_max_pending = NULL;
		json_object_object_get_ex(js_host, "pending", &js_max_pending);

		json_object* js_dbname = NULL;
		json_object_object_get_ex(js_host, "dbname", &js_dbname);
		if(NULL == js_user || NULL == js_passwd || NULL == js_ip || NULL == js_port || NULL == js_dbname){
			LOG_ERR("mysql config miss parameter.");
			has_failed = -1;
			continue;
		}

		mysql_inst_t* inst = wrapper->instances+i;
		inst->id = js_id?strdup(json_object_get_string(js_id)):NULL;
		inst->dbname = strdup(json_object_get_string(js_dbname));
		inst->charset = js_charset?strdup(json_object_get_string(js_charset)):NULL;

		const char* host = json_object_get_string(js_ip);
		int port = json_object_get_int(js_port);
		const char* user = json_object_get_string(js_user);
		const char* passwd = json_object_get_string(js_passwd);
		int max_pending_query = js_max_pending?json_object_get_int(js_max_pending):1000;

		inst->conn_inst = get_mysql_conn_inst(wrapper, host, port, user, passwd, max_pending_query);
		if(NULL == inst->conn_inst){
			has_failed = -2;
		}

#if 0
		inst->host = strdup(json_object_get_string(js_ip));
		inst->port = json_object_get_int(js_port);
		inst->user = strdup(json_object_get_string(js_user));
		inst->password = strdup(json_object_get_string(js_passwd));
		rc = connect_2_mysql_inst(wrapper->instances+i);
		if(rc){
			has_failed = -2;
		}
#endif
	}

	return has_failed;
}

mysql_inst_t* get_mysql_from_wrapper(mysql_wrapper_t* wrapper, uint64_t shard_key)
{
	if(0 == wrapper->num_instances){
		LOG_ERR("no mysql instances in wrapper");
		return NULL;
	}

	size_t idx = 0;
	if(wrapper->type == EN_MYSQL_WRAPPER_TYPE_SHARD){
		idx = shard_key%(wrapper->num_instances);
	}

	return wrapper->instances + idx;
}

mysql_inst_t* get_mysql_from_wrapper_by_id(mysql_wrapper_t* wrapper, const char* id)
{
	if(NULL == id){
		LOG_ERR("parmameter id is NULL");
		return NULL;
	}

	if(0 == wrapper->num_instances){
		LOG_ERR("no mysql instances in wrapper");
		return NULL;
	}

	for(size_t i = 0; i < wrapper->num_instances; ++i){
		mysql_inst_t* inst = wrapper->instances+i;
		if(inst->id && strcmp(inst->id, id) == 0){
			return inst;
		}
	}

	size_t idx = random() % (wrapper->num_instances);
	return wrapper->instances + idx;
}
#if 0
static int move_pointer_2_char(const char** p, char c)
{
	while(*(*p) != '\0' && *(*p) != c){
		*p = *p + 1;
	}

	if(*p == '\0')
		return -1;

	return 0;
}

static int parse_mysql_url(const char* url, mysql_inst_t* inst)
{
	const char* user = url;
	const char* password;
	const char* host;
	const char* port;
	const char* dbname;

	while(*user != 0 && !isalpha(*user)){
		++user;
	}

	if(*user == 0){
		goto invalid_mysql_url;
	}

	password = user;
	if(move_pointer_2_char(&password, ':')) goto invalid_mysql_url;

	host = password;
	if(move_pointer_2_char(&host, '@')) goto invalid_mysql_url;

	port = host;
	if(move_pointer_2_char(&port, ':')) goto invalid_mysql_url;

	dbname = port;
	move_pointer_2_char(&dbname, '/');
	if(*dbname == 0 || *(dbname+1) == 0) goto invalid_mysql_url;

	inst->host = strndup(host+1, port-host-1);
	inst->port = atoi(port+1);
	inst->user = strndup(user, password-user);
	inst->password = strndup(password+1, host-password-1);
	inst->dbname = strdup(dbname+1);

	return 0;
invalid_mysql_url:
	LOG_ERR("invalid mysql url:%s, correct format:\"user:password@host:port/dbname\"", url);
	return -1;
}
#endif

int connect_2_mysql_inst(mysql_conn_inst_t* inst)
{
	inst->prev = NULL;
	time_t now = time(NULL);
	if(now < inst->last_connect + 2){
		return -1;
	}

	mysql_init(&(inst->mysql));

	inst->last_connect = now;
	MYSQL* mysql = mysql_real_connect(&(inst->mysql), inst->host, inst->user, inst->password, NULL, inst->port, NULL, 0);
	if(NULL == mysql){
		LOG_ERR("failed to connect to mysql:%s:%s@%s:%d", inst->user, inst->password, inst->host, inst->port);
		return -2;
	}

	char reconnect = 1;
	mysql_options(&(inst->mysql), MYSQL_OPT_RECONNECT, (char *)&reconnect);

#if 0
	if(inst->charset){
		mysql_set_character_set(&(inst->mysql), inst->charset);
	}else{
		mysql_set_character_set(&(inst->mysql), "utf8");
	}
#endif

	inst->connected = 1;

	return 0;
}

mysql_query_t* mysql_malloc_query(rpc_ctx_t* ctx, MYSQL* mysql, const char* query)
{
	mysql_query_t* sql = (mysql_query_t*)calloc(1, sizeof(mysql_query_t));
	if(NULL == sql){
		return NULL;
	}


	//sql->mysql = mysql;
	sql->query = strdup(query);
	sql->flag_test = ctx->co->uctx.flag_test;

	sql->ctx = ctx;
	sql->async = ctx && ctx->co && ctx->co->pre;
	return sql;
}

uint64_t mysql_insert_id(mysql_query_t* query)
{
	return query->insert_id;
}

int64_t mysql_affected_rows(mysql_query_t* query)
{
	return query->affected_rows;
}

static int free_mysql_stmt(void* arg)
{
	MYSQL_STMT* stmt = (MYSQL_STMT*)arg;
	mysql_stmt_free_result(stmt);
	mysql_stmt_close(stmt);
	return 0;
}

static int free_mysql_res(void* arg)
{
	MYSQL_RES* res = (MYSQL_RES*)arg;
	mysql_free_result(res);
	return 0;
}

void mysql_free_query(mysql_query_t* query)
{
	if(NULL == query){
		return;
	}

	printf("##############free mysql query:%llu\n", (unsigned long long)query);

	if(query->query)
		free(query->query);

	if(query->req_binds.params){
		free(query->req_binds.params);
	}

	if(query->result_binds.params){
		free(query->result_binds.params);
	}

	if(query->stmt){
		if(query->async){
			add_task_2_routine((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer), free_mysql_stmt, (void*)query->stmt, true);
		}else{
			free_mysql_stmt(query->stmt);
		}
	}

	if(query->res){
		if(query->async){
			add_task_2_routine((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer), free_mysql_res, (void*)query->res, true);
		}else{
			free_mysql_res(query->res);
		}
	}

	free(query);
}

static void prepare_add_bind(mysql_binds_t* bind)
{
	if(NULL == bind){
		return;
	}

	int next_cap = bind->cap_binds?(bind->cap_binds<<1):10;
	if(bind->cap_binds == bind->num_binds){
		//CAUTION: if realloc failed, mem leak
		bind->params = (MYSQL_BIND*)realloc(bind->params, next_cap*sizeof(MYSQL_BIND));
		bind->cap_binds = next_cap;
	}
}

static MYSQL_BIND* get_next_bind(mysql_binds_t* binds)
{
	prepare_add_bind(binds);
	MYSQL_BIND* bind = binds->params+(binds->num_binds++);
	return bind;
}

int mysql_bind_tiny_int(mysql_query_t* query, int* value)
{
	if(NULL == query){
		return -1;
	}

	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_TINY;
	bind->buffer = (void*)value;
	bind->is_unsigned = 0;
	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_int(mysql_query_t* query, int* value)
{
	if(NULL == query){
		return -1;
	}

	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_LONG;
	bind->buffer = (void*)value;
	bind->is_unsigned = 0;
	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_uint(mysql_query_t* query, unsigned* value)
{
	if(NULL == query){
		return -1;
	}

	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_LONG;
	bind->buffer = (void*)value;

	bind->is_unsigned = 1;
	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_int64(mysql_query_t* query, int64_t* value)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_LONGLONG;
	bind->buffer = (void*)value;

	bind->is_unsigned = 0;
	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_uint64(mysql_query_t* query, uint64_t* value)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_LONGLONG;
	bind->buffer = (void*)value;

	bind->is_unsigned = 1;
	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_float(mysql_query_t* query, float* value)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_FLOAT;
	bind->buffer = (void*)value;
	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_doulbe(mysql_query_t* query, double* value)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_DOUBLE;
	bind->buffer = (void*)value;

	bind->is_null = 0;
	bind->length = 0;
	return 0;
}

int mysql_bind_str(mysql_query_t* query, char* value, size_t* len)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_STRING;
	bind->buffer = (void*)value;

	bind->is_null_value = 0;
	bind->is_null = 0;

	bind->length = len;
	bind->buffer_length = *len;
	return 0;
}

int mysql_bind_var_str(mysql_query_t* query, char* value, size_t* len)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_VAR_STRING;
	bind->buffer = (void*)value;

	bind->is_null_value = 0;
	bind->is_null = 0;

	bind->length = len;
	bind->buffer_length = *len;
	return 0;
}
int mysql_bind_binary(mysql_query_t* query, char* value, size_t* len)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->req_binds));
	bind->buffer_type = MYSQL_TYPE_BLOB;
	bind->buffer = (void*)value;

	bind->is_null_value = 0;
	bind->is_null = 0;

	bind->length = len;
	bind->buffer_length = *len;
	return 0;
}

int switch_dbname_charset(mysql_inst_t* inst, int flag)
{
	int rc = 0;
	char dbname[256];
	if(flag){
		snprintf(dbname, sizeof(dbname), "%s_test", inst->dbname);
	}else{
		snprintf(dbname, sizeof(dbname), "%s", inst->dbname);
	}

	if(flag != inst->flag || inst->conn_inst->prev != inst){
		if(inst->charset){
			mysql_set_character_set(&(inst->conn_inst->mysql), inst->charset);
		}else{
			mysql_set_character_set(&(inst->conn_inst->mysql), "utf8");
		}

		rc = mysql_select_db(&(inst->conn_inst->mysql), dbname);
		inst->conn_inst->prev = inst;
		inst->flag = flag;
	}

	if(rc){
		LOG_ERR("failed to switch dbname:%s, error:%d:%s", inst->dbname, rc, mysql_error(&(inst->conn_inst->mysql)));
		inst->conn_inst->prev = NULL;
	}

	return rc;
}

static int check_mysql_status(mysql_query_t* query)
{
	mysql_inst_t* inst = query->ctx->mysql_inst;

	time_t now = time(NULL);
	if(now < inst->conn_inst->last_ping + 5){
		return switch_dbname_charset(inst, query->flag_test);
	}

	if(mysql_ping(&(inst->conn_inst->mysql))){
		LOG_ERR("failed to reconnect mysql");
		return -123;
	}

	inst->conn_inst->last_ping = now;
	return switch_dbname_charset(inst, query->flag_test);
}

void async_fin_mysql_execute(mysql_query_t* query)
{
	rpc_ctx_t* ctx = query->ctx;
	coroutine_t* co = ctx->co;
	co_resume(co);
	co_release(&co);
}

static int do_stmt_execute(void* arg)
{
	mysql_query_t* query = (mysql_query_t*)arg;
	int rc = check_mysql_status(query);
	if(rc){
		LOG_ERR("mysql status not ok");
		goto end_exe;
	}

	query->stmt = mysql_stmt_init(&(query->ctx->mysql_inst->conn_inst->mysql));
	if(NULL == query->stmt){
		goto end_exe;
	}

	rc = mysql_stmt_prepare(query->stmt, query->query, strlen(query->query));
	if(rc){
		rc = -2;
		goto end_exe;
	}

	if(query->req_binds.params && mysql_stmt_bind_param(query->stmt, query->req_binds.params)){
		rc = -3;
		goto end_exe;
	}

	if(query->result_binds.params && mysql_stmt_bind_result(query->stmt, query->result_binds.params)){
		rc = -4;
		goto end_exe;
	}

	if(mysql_stmt_execute(query->stmt)){
		LOG_ERR("failed to execute mysql query");
		rc = -5;
		goto end_exe;
	}

	if(query->result_binds.params && mysql_stmt_store_result(query->stmt)){
		LOG_ERR("failed to execute mysql query");
		rc = -6;
		goto end_exe;
	}

	query->insert_id = mysql_insert_id(&(query->ctx->mysql_inst->conn_inst->mysql));
	query->affected_rows = mysql_affected_rows(&(query->ctx->mysql_inst->conn_inst->mysql));

end_exe:
	query->rc = rc;

	if(!query->async){
		return rc;
	}

	cmd_t cmd;
	cmd.cmd = K_CMD_NOTIFY_ASYNC_DB_ROUTINE_FIN;
	cmd.arg = query;
	if(notify_worker((worker_thread_t*)(query->ctx->co->worker), cmd)){
		LOG_ERR("[ALARM]FATAL failed to notify async db routine fin");
		//mysql_free_query(query);
	}

	return rc;
}

int execute_mysql_query(mysql_query_t* query)
{
	if(NULL == query || NULL == query->ctx || NULL == query->ctx->mysql_inst || NULL == query->query){
		return -1;
	}

	struct timeval macro_start;
	struct timeval macro_end;
	gettimeofday(&macro_start, NULL);

	int rc = 0;
	if(!query->async){
		do_stmt_execute(query);
	}else{
		LOG_INFO("BEFORE QUEUE SIZE: %llu", ((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer))->cnt_task);
		rc = add_task_2_routine((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer), do_stmt_execute, (void*)query);
		if(!rc){
			co_yield(query->ctx->co);
		}else{
			LOG_ERR("[MYSQL_ALARM]failed to add async mysql task");
			MONITOR_ACC("qpm_mysql_async_failed", 1);
		}
		LOG_INFO("AFTER QUEUE SIZE: %llu", ((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer))->cnt_task);
	}

	rc = query->rc;

	gettimeofday(&macro_end, NULL);
	int milli_cost = 1000*(macro_end.tv_sec-macro_start.tv_sec) +(macro_end.tv_usec-macro_start.tv_usec)/1000;
	MONITOR_ACC("cost_mysql_execute", milli_cost);
	MONITOR_ACC("qpm_mysql_execute", 1);
	if(query->stmt){
		query->reslt.mysql_errno = mysql_stmt_errno(query->stmt);
		query->reslt.mysql_errmsg = mysql_stmt_error(query->stmt);
	}else{
		rc = -1;
		query->reslt.mysql_errno = -1;
		query->reslt.mysql_errmsg = msg_mysql_stucked;
	}

	return rc;
}

static int do_query(void* arg)
{
	mysql_query_t* query = (mysql_query_t*)arg;
	int rc = check_mysql_status(query);
	if(rc){
		LOG_ERR("mysql status not ok");
		goto end_exe;
	}

	rc = mysql_query(&(query->ctx->mysql_inst->conn_inst->mysql), query->query);
	if(rc){
		rc = -2;
		goto end_exe;
	}

    query->res = mysql_store_result(&(query->ctx->mysql_inst->conn_inst->mysql));
    rc = mysql_errno(&(query->ctx->mysql_inst->conn_inst->mysql));
	if(rc){
		goto end_exe;
	}

end_exe:
	query->rc = rc;

	if(!query->async){
		return rc;
	}

	cmd_t cmd;
	cmd.cmd = K_CMD_NOTIFY_ASYNC_DB_ROUTINE_FIN;
	cmd.arg = query;
	if(notify_worker((worker_thread_t*)(query->ctx->co->worker), cmd)){
		LOG_ERR("[ALARM]FATAL failed to notify async db routine fin");
		//mysql_free_query(query);
	}

	return rc;
}

int execute_query(mysql_query_t* query)
{
	if(NULL == query || NULL == query->ctx || NULL == query->ctx->mysql_inst || NULL == query->query){
		return -1;
	}

	struct timeval macro_start;
	struct timeval macro_end;
	gettimeofday(&macro_start, NULL);

	int rc = 0;
	if(!query->async){
		do_query(query);
	}else{
		LOG_INFO("BEFORE QUEUE SIZE: %llu", ((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer))->cnt_task);
		rc = add_task_2_routine((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer), do_query, (void*)query);
		if(!rc){
			co_yield(query->ctx->co);
		}else{
			LOG_ERR("[MYSQL_ALARM]failed to add async mysql task");
			MONITOR_ACC("qpm_mysql_async_failed", 1);
		}
		LOG_INFO("AFTER QUEUE SIZE: %llu", ((async_routine_t*)(query->ctx->mysql_inst->conn_inst->asyncer))->cnt_task);
	}

	rc = query->rc;

	gettimeofday(&macro_end, NULL);
	int milli_cost = 1000*(macro_end.tv_sec-macro_start.tv_sec) +(macro_end.tv_usec-macro_start.tv_usec)/1000;
	MONITOR_ACC("cost_mysql_execute", milli_cost);
	MONITOR_ACC("qpm_mysql_execute", 1);

	return rc;
}

int mysql_result_bind_int(mysql_query_t* query, int* value, my_bool* is_null, unsigned long* length, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_LONG;
	bind->buffer = (void*)value;
	bind->is_null = is_null;
	bind->length = length;
	bind->error = error;
	bind->is_unsigned = 0;

	return 0;
}

int mysql_result_bind_uint(mysql_query_t* query, unsigned* value, my_bool* is_null, unsigned long* length, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));

	bind->buffer_type = MYSQL_TYPE_LONG;
	bind->buffer = (void*)value;
	bind->is_null = is_null;
	bind->length = length;
	bind->is_unsigned = 1;
	bind->error = error;

	return 0;
}

int mysql_result_bind_int64(mysql_query_t* query, int64_t* value, my_bool* is_null, unsigned long* length, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_LONGLONG;
	bind->buffer = (void*)value;

	bind->is_null = is_null;
	bind->length = length;
	bind->error = error;
	bind->is_unsigned = 0;
	return 0;
}

int mysql_result_bind_uint64(mysql_query_t* query, uint64_t* value, my_bool* is_null, unsigned long* length, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_LONGLONG;
	bind->buffer = (void*)value;

	bind->is_null = is_null;
	bind->length = length;
	bind->is_unsigned = 1;
	bind->error = error;
	return 0;
}

int mysql_result_bind_float(mysql_query_t* query, float* value, my_bool* is_null, unsigned long* length, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_FLOAT;
	bind->buffer = (void*)value;

	bind->is_null = is_null;
	bind->length = length;
	bind->error = error;
	return 0;
}

int mysql_result_bind_doulbe(mysql_query_t* query, double* value, my_bool* is_null, unsigned long* length, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_DOUBLE;
	bind->buffer = (void*)value;
	bind->is_null = is_null;
	bind->length = length;
	bind->error = error;
	return 0;
}

int mysql_result_bind_str(mysql_query_t* query, char* value, my_bool* is_null, size_t* len, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_STRING;
	bind->buffer = (void*)value;
	bind->buffer_length = *len;
	bind->is_null = is_null;
	bind->length = len;
	bind->error = error;
	return 0;
}

int mysql_result_bind_binary(mysql_query_t* query, char* value, my_bool* is_null, size_t* len, my_bool* error)
{
	if(NULL == query){
		return -1;
	}
	MYSQL_BIND* bind = get_next_bind(&(query->result_binds));
	bind->buffer_type = MYSQL_TYPE_BLOB;
	bind->buffer = (void*)value;
	bind->buffer_length = *len;
	bind->is_null = is_null;
	bind->length = len;
	bind->error = error;
	return 0;
}

int mysql_enumerate_rslt(mysql_query_t* query, fn_handle_row handler, void* buff, void* ctx)
{
	if(/*NULL == handler || */NULL == query){
		return -1;
	}

	if(!query->stmt){
		LOG_ERR("query stmt is NULL");
		return -2;
	}

    size_t count = 0;
	while (!mysql_stmt_fetch(query->stmt)){
        count++;
		if (handler) handler(buff, ctx);
	}
    return count;
}

MYSQL* get_mysql_from_rpc(rpc_ctx_t* ctx, uint64_t shard_key)
{
	if(NULL == ctx || NULL == ctx->ptr || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return NULL;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	mysql_inst_t* inst = get_mysql_from_wrapper(&(worker->mysql_wrapper), shard_key);
	if(NULL == inst){
		LOG_ERR("failed to get mysql instance");
		return NULL;
	}
	if(!inst->conn_inst){
		LOG_ERR("impossible here. failed to get mysql inst:%" PRIu64, shard_key);
		return NULL;
	}

	if(!inst->conn_inst->connected && connect_2_mysql_inst(inst->conn_inst)){
		return NULL;
	}

	ctx->mysql_inst = inst;
	return &(inst->conn_inst->mysql);
}

MYSQL* get_mysql_from_rpc_by_id(rpc_ctx_t* ctx, const char* id)
{
	if(NULL == ctx || NULL == ctx->ptr || NULL == ctx->co->worker){
		LOG_ERR("no worker in ctx");
		return NULL;
	}

	worker_thread_t* worker = (worker_thread_t*)(ctx->co->worker);
	mysql_inst_t* inst = get_mysql_from_wrapper_by_id(&(worker->mysql_wrapper), id);
	if(NULL == inst){
		LOG_ERR("failed to get mysql instance");
		return NULL;
	}
	if(NULL == inst->conn_inst){
		LOG_ERR("impossible here, no conn inst for mysql inst:%s", id);
		return NULL;
	}


	if(!inst->conn_inst->connected && connect_2_mysql_inst(inst->conn_inst)){
		return NULL;
	}

	ctx->mysql_inst = inst;
	return &(inst->conn_inst->mysql);
}

int connect_2_mysql(worker_thread_t* wt, json_object* config)
{
	return init_wrapper_with_config(&(wt->mysql_wrapper), config);
}
