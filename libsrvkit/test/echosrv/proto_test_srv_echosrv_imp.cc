#include <proto_test_srv_echosrv_imp.h>
#include <stdio.h>

struct table_row_t
{
	unsigned id;
	my_bool is_id_null;
	unsigned long id_length;
	my_bool id_error;

	char name[16];
	my_bool is_name_null;
	unsigned long name_length;
	my_bool name_error;

	unsigned age;
	my_bool is_age_null;
	unsigned long age_length;
	my_bool age_error;
};

static void fn_enumerate_table(void* arg1, void* arg2)
{
	table_row_t* row = (table_row_t*)(arg1);
	//printf("id:%u\tname:%s\tage:%d\t\n", row->id, row->name, row->age);
}

int do_test_srv_echosrv_echo(rpc_ctx_t* ctx, test_srv::echo_request* req, test_srv::echo_response* rsp)
{
	rsp->set_content(req->content());
	return 0;

	printf("echosrv recv req:%s\n", req->content().c_str());
	MYSQL* mysql = get_mysql_from_rpc_by_id(ctx, "test");
	if(NULL == mysql){
		LOG_ERR("failed to get mysql");
		printf("failed to get mysql\n");
		return 0;
	}


	char sz_name[16];
	int now = time(NULL);
	snprintf(sz_name, 16, "%d", now);
	mysql_query_t* query = mysql_malloc_query(ctx, mysql, "INSERT INTO person_like SET name=? , age=18;");
	size_t len = strlen(sz_name);
	mysql_bind_str(query, sz_name, &len);
	execute_mysql_query(query);
	mysql_free_query(query);
	//printf("### end echo ###\n");

	table_row_t row;
	memset(&row, 0, sizeof(row));
	query = mysql_malloc_query(ctx, mysql, "select id, name, age from person_like;");

	mysql_result_bind_uint(query, &row.id, &row.is_id_null, &row.id_length, &row.id_error);
	row.name_length = 16;
	mysql_result_bind_str(query, row.name, &row.is_name_null, &row.name_length, &row.name_error);
	mysql_result_bind_uint(query, &row.age, &row.is_age_null, &row.age_length, &row.age_error);

	execute_mysql_query(query);
	mysql_enumerate_rslt(query, fn_enumerate_table, &row, NULL);
	mysql_free_query(query);


	call_redis(ctx, "set test %d", 123);
	call_redis(ctx, "set test1 %d", 123);

	struct timeval start;
	gettimeofday(&start, NULL);

	begin_redis_pipeline(ctx);
	call_add_pipeline_command(ctx, "set wilestest1 %d", 1);
	call_add_pipeline_command(ctx, "set wilestest2 %d", 2);
	call_add_pipeline_command(ctx, "set wilestest3 %d", 3);
	call_add_pipeline_command(ctx, "set wilestest4 %d", 4);
	call_add_pipeline_command(ctx, "set wilestest5 %d", 5);
	call_add_pipeline_command(ctx, "set wilestest6 %d", 6);
	end_redis_pipeline(ctx);
	begin_redis_pipeline(ctx);
	call_add_pipeline_command(ctx, "get wilestest1");
	call_add_pipeline_command(ctx, "get wilestest2");
	call_add_pipeline_command(ctx, "get wilestest3");
	call_add_pipeline_command(ctx, "get wilestest4");
	call_add_pipeline_command(ctx, "get wilestest5");
	call_add_pipeline_command(ctx, "get wilestest6");

	redisReply* r;
	while((r = get_pipeline_reply(ctx))){
		printf("reply:%s\n", r->str);
	}
	end_redis_pipeline(ctx);

	struct timeval end;
	gettimeofday(&end, NULL);
	uint64_t milli_cost = 1000*(end.tv_sec-start.tv_sec)+(end.tv_usec-start.tv_usec)/1000;
	printf("########impl cost:%llu######\n", milli_cost);

	return 0;
}

