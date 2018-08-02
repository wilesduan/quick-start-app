#ifndef __LIBSRVKIT_MYSQL_WRAPPER__
#define __LIBSRVKIT_MYSQL_WRAPPER__

#include <mysql.h>
#include <time.h>
#include <json.h>
#include <rbtree.h>
#include <async_task.h>

enum mysql_wrapper_type
{
	EN_MYSQL_WRAPPER_TYPE_SHARD = 1,
	EN_MYSQL_WRAPPER_TYPE_FABRIC = 2,
};

struct mysql_inst_t;

typedef struct mysql_conn_inst_t
{
	char* host;
	int port;

	char* user;
	char* password;

	size_t max_pending_query;

	MYSQL mysql;
	time_t last_ping;
	time_t last_connect;
	int connected;

	struct mysql_inst_t* prev;

	rb_node node;

	async_routine_t* asyncer;
}mysql_conn_inst_t;

typedef struct mysql_inst_t
{
	char* id;
	char* dbname;
	mysql_conn_inst_t* conn_inst;
	char* charset;
	int flag;
}mysql_inst_t;

typedef struct mysql_wrapper_t
{
	mysql_wrapper_type type;
	size_t num_instances;
	mysql_inst_t* instances;
	rb_root conn_insts;
}mysql_wrapper_t;

typedef struct mysql_binds_t
{
	size_t cap_binds;
	size_t num_binds;
	MYSQL_BIND* params;
}mysql_binds_t;

typedef struct mysql_resl_t
{
	int mysql_errno;
	const char* mysql_errmsg;
}mysql_resl_t;

struct rpc_ctx_t;
typedef struct mysql_query_t
{
	//MYSQL* mysql;
	char* query;

	mysql_binds_t req_binds;
	mysql_binds_t result_binds;

	MYSQL_STMT* stmt;
	MYSQL_RES*  res;

	struct mysql_resl_t reslt;

	rpc_ctx_t* ctx;
	bool async;
	//mysql_inst_t* inst;

	int flag_test;
	int rc;
	uint64_t insert_id;
	int64_t affected_rows;
}mysql_query_t;

mysql_query_t* mysql_malloc_query(rpc_ctx_t* ctx, MYSQL* mysql, const char* query);

void mysql_free_query(mysql_query_t*);
typedef void(*fn_handle_row)(void*, void*);
int mysql_enumerate_rslt(mysql_query_t* query, fn_handle_row handler, void* buff, void* ctx);
uint64_t mysql_insert_id(mysql_query_t*);
int64_t mysql_affected_rows(mysql_query_t* query);

//bind query
int mysql_bind_tiny_int(mysql_query_t* query, int* value);
int mysql_bind_int(mysql_query_t* query, int* value);
int mysql_bind_uint(mysql_query_t* query, unsigned* value);
int mysql_bind_int64(mysql_query_t* query, int64_t* value);
int mysql_bind_uint64(mysql_query_t* query, uint64_t* value);
int mysql_bind_float(mysql_query_t* query, float* value);
int mysql_bind_doulbe(mysql_query_t* query, double* value);
int mysql_bind_str(mysql_query_t* query, char* sz_str, size_t* len);
int mysql_bind_var_str(mysql_query_t* query, char* sz_str, size_t* len);
int mysql_bind_binary(mysql_query_t* query, char* binary, size_t* len);

//bind result select query
int mysql_result_bind_int(mysql_query_t* query, int* value, my_bool* is_null, unsigned long* length, my_bool* error);
int mysql_result_bind_uint(mysql_query_t* query, unsigned* value, my_bool* is_null, unsigned long* length, my_bool* error);
int mysql_result_bind_int64(mysql_query_t* query, int64_t* value, my_bool* is_null, unsigned long* length, my_bool* error);
int mysql_result_bind_uint64(mysql_query_t* query, uint64_t* value, my_bool* is_null, unsigned long* length, my_bool* error);
int mysql_result_bind_float(mysql_query_t* query, float* value, my_bool* is_null, unsigned long* length, my_bool* error);
int mysql_result_bind_doulbe(mysql_query_t* query, double* value, my_bool* is_null, unsigned long* length, my_bool* error);
int mysql_result_bind_str(mysql_query_t* query, char* sz_str, my_bool* is_null, size_t* len, my_bool* error);
int mysql_result_bind_binary(mysql_query_t* query, char* binary, my_bool* is_null, size_t* len, my_bool* error);

int execute_mysql_query(mysql_query_t* query);
int execute_query(mysql_query_t* query);

int init_wrapper_with_config(mysql_wrapper_t* wrapper, json_object* conf);
int connect_2_mysql_inst(mysql_conn_inst_t* inst);
/*
int set_mysql_bind_int_32(MYSQL_BIND* bind, const char* column, const int* value)
int set_mysql_bind_uint_32(MYSQL_BIND* bind, const char* column, const uint32_t* value)
int set_mysql_bind_uint_ll(MYSQL_BIND* bind, const char* column, const unsigned long long* value)
int set_mysql_bind_float(MYSQL_BIND* bind, const char* column, const float* value)
int set_mysql_bind_double(MYSQL_BIND* bind, const char* column, const double* value)
int set_mysql_bind_string(MYSQL_BIND* bind, const char* column, const char* value)
int set_mysql_bind_binary(MYSQL_BIND* bind, const char* column, const char* value, unsigned long len)
*/

mysql_inst_t* get_mysql_from_wrapper(mysql_wrapper_t* wrapper, uint64_t shard_key);
mysql_inst_t* get_mysql_from_wrapper_by_id(mysql_wrapper_t* wrapper, const char* id);
void async_fin_mysql_execute(mysql_query_t* query);

#endif//__LIBSRVKIT_MYSQL_WRAPPER__

