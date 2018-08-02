#include "mysql_wrapper.h"
#include <json.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


typedef struct row_t
{
    uint64_t uid;
    my_bool is_uid_null;
    unsigned long uid_len;
	my_bool uid_error;

    uint64_t op_seqno;
    my_bool is_op_seqno_null;
    unsigned long op_seqno_len;
	my_bool op_seqno_error;

    uint64_t op_target;
    my_bool is_op_target_null;
    unsigned long op_target_len;
	my_bool op_target_error;

    uint64_t op_context;
    my_bool is_op_context_null;
    unsigned long op_context_len;
	my_bool op_context_error;

    int op_type;
    my_bool is_op_type_null;
    unsigned long op_type_len;
	my_bool op_type_error;

    void* ptr;
	row_t(){
		uid_len = sizeof(uint64_t);
		is_uid_null = 0;
		uid_error = 0;

		is_op_seqno_null = 0;
		op_seqno_len = sizeof(uint64_t);
		op_seqno_error = 0;

		is_op_target_null = 0;
		op_target_len = sizeof(uint64_t);
		op_target_error = 0;

		is_op_context_null = 0;
		op_context_len = sizeof(uint64_t);
		op_context_error = 0;

		is_op_type_null = 0;
		op_type_len = sizeof(int);
		op_type_error = 0;
	}
}row_t;

void fn_fetch_row(void* buff, void* ctx)
{
	row_t* row = (row_t*)buff;
	printf("uid:%llu, op_seqno:%llu, op_target:%llu, op_context:%llu, op_type:%llu\n", row->uid, row->op_seqno, row->op_target, row->op_context, row->op_type);
	return;
	//printf("%s\n", (char*)buff);
}
int main()
{
	mysql_wrapper_t wrapper;
	const char* str = "{\"type\":\"shard\", \"hosts\":[{\"user\":\"live\", \"passwd\":\"oWni@ElNs0P0C(dphdj*F1y4\", \"ip\":\"172.16.71.233\", \"port\":3306, \"dbname\":\"link_inbox\"}]}";
	json_object* conf = json_tokener_parse(str);
	if(NULL == conf){
		printf("faield to parse token\n");
		return -1;
	}

	int rc = init_wrapper_with_config(&wrapper, conf);
	if(rc){
		printf("failed to connect to mysql\n");
		return -2;
	}

    const char* select = "select uid, op_seqno, op_target, op_context, op_type from t_op_binlog where uid = ? and op_seqno >= ? and op_seqno <= ?"; 
	mysql_query_t* query = mysql_malloc_query(&(wrapper.instances[0].mysql), select);
    uint64_t uid = 1234;
    uint64_t op_begin_seqno = 1000;
    uint64_t op_end_seqno = 2222;
	mysql_bind_uint64(query, &uid);
	mysql_bind_uint64(query, &op_begin_seqno);
	mysql_bind_uint64(query, &op_end_seqno);

	row_t row;
	mysql_result_bind_uint64(query, &row.uid, &row.is_uid_null, &row.uid_len, &row.uid_error);
	mysql_result_bind_uint64(query, &row.op_seqno, &row.is_op_seqno_null, &row.op_seqno_len, &row.op_seqno_error);
	mysql_result_bind_uint64(query, &row.op_target, &row.is_op_target_null, &row.op_target_len, &row.op_target_error);
	mysql_result_bind_uint64(query, &row.op_context, &row.is_op_context_null, &row.op_context_len, &row.op_context_error);
	mysql_result_bind_int(query, &row.op_type, &row.is_op_type_null, &row.op_type_len, &row.op_type_error);
	rc = execute_mysql_query(query);
	if(rc){
		printf("failed to execute query:%s\n", query->reslt.mysql_errmsg);
	}else{
		mysql_enumerate_rslt(query, fn_fetch_row, &row, NULL);
	}

#if 0
	const char* q = "select msg_content from t_msg_02 where msg_key=?";
	const char* insert = "insert into t_msg_02 (msg_key, sender_device, receive_type, sender_uid, msg_content, timestamp) values(?,?,?,?,?,?)"; 

	mysql_query_t* query = mysql_malloc_query(&(wrapper.instances[0].mysql), insert);
	uint64_t key = 123456789;
	mysql_bind_uint64(query, &key);

	int send_device=3;
	mysql_bind_int(query,&send_device);

	int recv_type = 4;
	mysql_bind_int(query,&recv_type);

	uint64_t send_uid = 5;
	mysql_bind_uint64(query,&send_uid);

	char msg_content[100]; 
	sprintf(msg_content, "inserted by mysql_query_t");
	size_t len = strlen(msg_content);
	mysql_bind_str(query, msg_content, &len);

	time_t now = time(NULL);
	mysql_bind_int(query, (int*)&now);

	/*
	struct row r;
	size_t len = sizeof(r.sz_content);
	my_bool is_null = 0;
	mysql_result_bind_str(query, &(r.sz_content), &is_null, &len);
	*/
	rc = execute_mysql_query(query);
	if(rc){
		printf("failed to execute query:%s\n", query->reslt.mysql_errmsg);
	}

	//mysql_enumerate_rslt(query, fn_fetch_row, sz_content);
#endif
	return 0;
}
