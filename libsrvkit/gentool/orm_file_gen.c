#include "orm_file_gen.h"
#include <stdio.h>
#include "y.tab.h"
#include <assert.h>
#include <unistd.h>
#include "file_gen.h"
#include <string.h>

extern std::vector<t_mysql_query> g_querys;
extern t_mysql_query* pquery;
extern std::string package;

field_2_str_t field_2_str[EN_MYSQL_FIELD_LAST_ONE] = {
	[EN_MYSQL_FIELD_TINY_INT] = {"int", "0", "mysql_bind_tiny_int", "mysql_result_bind_int"},
	[EN_MYSQL_FIELD_INT32] = {"int", "0", "mysql_bind_int", "mysql_result_bind_int" },
	[EN_MYSQL_FIELD_INT64] = {"int64_t", "0", "mysql_bind_int64", "mysql_result_bind_int64" },
	[EN_MYSQL_FIELD_UINT32] = {"unsigned", "0", "mysql_bind_uint", "mysql_result_bind_uint" },
	[EN_MYSQL_FIELD_UINT64] = {"uint64_t", "0", "mysql_bind_uint64", "mysql_result_bind_uint64" },
	[EN_MYSQL_FIELD_FLOAT] = {"float", "0", "mysql_bind_float", "mysql_result_bind_float" },
	[EN_MYSQL_FIELD_DOUBLE] = {"double", "0", "mysql_bind_doulbe", "mysql_result_bind_doulbe" },
	[EN_MYSQL_FIELD_STR] = {"char*", "NULL", "mysql_bind_str", "mysql_result_bind_str" },
	[EN_MYSQL_FIELD_VAR_STR] = {"char*", "NULL", "mysql_bind_var_str", "mysql_result_bind_str" },
	[EN_MYSQL_FIELD_BINARY] = {"char*", "NULL", "mysql_bind_binary", "mysql_result_bind_binary" },
};

static int gen_header_file(const std::string& package, const std::vector<t_mysql_query>& querys, const char* out_dir);
static int gen_cc_file(const std::string& package, const std::vector<t_mysql_query>& querys, const char* out_dir);
static void gen_select_header(FILE* fp, const std::string& package, const t_mysql_query& query);
static void gen_insert_header(FILE* fp, const std::string& package, const t_mysql_query& query);
static void gen_update_header(FILE* fp, const std::string& package, const t_mysql_query& query);

static void gen_select_cc(FILE* fp, const std::string& package, const t_mysql_query& query);
static void gen_insert_cc(FILE* fp, const std::string& package, const t_mysql_query& query);
static void gen_update_cc(FILE* fp, const std::string& package, const t_mysql_query& query);


void gen_mysql_orm_functions(const std::string& package, const std::vector<t_mysql_query>& querys, const char* out_dir)
{
	char sz_orm_dir[1024];
	out_dir?snprintf(sz_orm_dir, sizeof(sz_orm_dir), "%s", out_dir):snprintf(sz_orm_dir, sizeof(sz_orm_dir), "./");
	int rc = do_mkdir(sz_orm_dir);
	if(rc){
		printf("failed to mkdir:%s\n", sz_orm_dir);
		assert(0);
		return;
	}

	rc = gen_header_file(package, querys, sz_orm_dir);
	if(rc){
		perror("failed to gen header file");
		assert(0);
		return;
	}

	rc = gen_cc_file(package, querys, sz_orm_dir);
	if(rc){
		perror("failed to gen cc file");
		assert(0);
		return;
	}

	return;

	//field_op_funcs op_funcs[EN_MYSQL_FIELD_LAST_ONE];
	printf("package:%s\n", package.data());
	for(size_t i = 0; i < querys.size(); ++i){
		const t_mysql_query& query = querys[i];
		printf("define:%d:%s\n", query.type, query.tag.data());
		printf("sql:%s\n", query.sql.data());
		for(size_t j = 0; j < query.columns.size(); ++j){
			const t_field& field = query.columns[j];
			printf("column:%s:%s\n", field.column_name.data(), field.column_type.data());
		}

		for(size_t j = 0; j < query.conditions.size(); ++j){
			const t_field& field = query.conditions[j];
			printf("condition:%s:%s\n", field.column_name.data(), field.column_type.data());
		}

		for(size_t j = 0; j < query.updates.size(); ++j){
			const t_field& field = query.updates[j];
			printf("update:%s:%s\n", field.column_name.data(), field.column_type.data());
		}
	}
}

int gen_header_file(const std::string& package, const std::vector<t_mysql_query>& querys, const char* out_dir)
{
	char sz_header_file[1024];
	snprintf(sz_header_file, sizeof(sz_header_file), "%s/%s_mysql_orm.h", out_dir, package.data());
	FILE* fp = fopen(sz_header_file, "w");
	if(!fp){
		assert(0);
		printf("failed to open file:%s\n", sz_header_file);
		return 1;
	}

	fprintf(fp, "#ifndef __%s_MYSQL_ORM_H__\n", package.data());
	fprintf(fp, "#define __%s_MYSQL_ORM_H__\n", package.data());

	fprintf(fp, "\n#include <server.h>\n");

	fprintf(fp, "\n#ifndef __MYSQL_OP_DB_SELECTOR__\n");
	fprintf(fp, "#define __MYSQL_OP_DB_SELECTOR__\n");
	fprintf(fp, "#define EN_INVALID_DB_SELECTOR 199999;\n");
	fprintf(fp, "typedef struct mysql_selector_t\n");
	fprintf(fp, "{\n");
	fprintf(fp, "\tconst char* db_id;\n");
	fprintf(fp, "\tuint64_t shard_key;\n\n");
	fprintf(fp, "\tconst char* table;\n");
	fprintf(fp, "}mysql_selector_t;\n");
	fprintf(fp, "#endif//__MYSQL_OP_DB_SELECTOR__\n\n");


	for(size_t i = 0; i < querys.size(); ++i){
		const t_mysql_query& query = querys[i];
		switch(query.type){
			case EN_MYSQL_QUERY_SELECT:
				gen_select_header(fp, package, query);
				break;
			case EN_MYSQL_QUERY_INSERT:
				gen_insert_header(fp, package, query);
				break;
			case EN_MYSQL_QUERY_UPDATE:
				gen_update_header(fp, package, query);
				break;
			default:
				break;
		}
	}
	fprintf(fp, "#endif//__%s_MYSQL_ORM_H__", package.data());
	fclose(fp);
	return 0;
}

EN_MYSQL_FIELD_TYPE get_mysql_field_type(const char* type)
{
	if(strcmp(type, "int8") == 0){
		return EN_MYSQL_FIELD_TINY_INT;
	}else if(strcmp(type, "int32") == 0){
		return EN_MYSQL_FIELD_INT32;
	}else if(strcmp(type, "int64") == 0){
		return EN_MYSQL_FIELD_INT64;
	}else if(strcmp(type, "uint32") == 0){
		return EN_MYSQL_FIELD_UINT32;
	}else if(strcmp(type, "uint64") == 0){
		return EN_MYSQL_FIELD_UINT64;
	}else if(strcmp(type, "float") == 0){
		return EN_MYSQL_FIELD_FLOAT;
	}else if(strcmp(type, "double") == 0){
		return EN_MYSQL_FIELD_DOUBLE;
	}else if(strcmp(type, "string") == 0){
		return EN_MYSQL_FIELD_STR;
	}else if(strcmp(type, "binary") == 0){
		return EN_MYSQL_FIELD_BINARY;
	}

	printf("invalid type:%s\n", type);
	assert(0);
	return EN_MYSQL_FIELD_LAST_ONE;
}

void fprintf_field_in_member(FILE* fp, const t_field& field)
{
	EN_MYSQL_FIELD_TYPE type = get_mysql_field_type(field.column_type.data());
	fprintf(fp, "\t%s %s;\n", field_2_str[type].data_type, field.column_name.data());
	if(type == EN_MYSQL_FIELD_BINARY || type == EN_MYSQL_FIELD_STR || type == EN_MYSQL_FIELD_VAR_STR){
		fprintf(fp, "\tsize_t %s_len;\n", field.column_name.data());
	}
}

void fprintf_field_in_construct(FILE* fp, const t_field& field)
{
	EN_MYSQL_FIELD_TYPE type = get_mysql_field_type(field.column_type.data());
	fprintf(fp, "\t\t%s = %s;\n", field.column_name.data(), field_2_str[type].default_value);
	if(type == EN_MYSQL_FIELD_BINARY || type == EN_MYSQL_FIELD_STR || type == EN_MYSQL_FIELD_VAR_STR){
		fprintf(fp, "\t\t%s_len = 0;\n", field.column_name.data());
	}
}

void fprintf_field_in_destruct(FILE* fp, const t_field& field)
{
	switch(get_mysql_field_type(field.column_type.data())){
		case EN_MYSQL_FIELD_STR:
		case EN_MYSQL_FIELD_BINARY:
			fprintf(fp, "\t\tfree(%s);\n", field.column_name.data());
			break;
		default:
			break;
	}
}

void gen_select_header(FILE* fp, const std::string& package, const t_mysql_query& query)
{
	fprintf(fp, "typedef struct %s_select_%s_result_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_field_in_member(fp, query.columns[i]);
	}

	fprintf(fp, "\t%s_select_%s_result_t()\n", package.data(), query.tag.data());
	fprintf(fp, "\t{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_field_in_construct(fp, query.columns[i]);
	}
	fprintf(fp, "\t}\n");

	fprintf(fp, "\t~%s_select_%s_result_t()\n", package.data(), query.tag.data());
	fprintf(fp, "\t{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_field_in_destruct(fp, query.columns[i]);
	}
	fprintf(fp, "\t}\n");
	fprintf(fp, "}%s_select_%s_result_t;\n", package.data(), query.tag.data());


	fprintf(fp, "typedef struct %s_select_%s_condition_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.conditions.size(); ++i){
		fprintf_field_in_member(fp, query.conditions[i]);
	}
	fprintf(fp, "}%s_select_%s_condition_t;\n", package.data(), query.tag.data());

	fprintf(fp, "typedef struct %s_select_%s_row_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		const t_field& field = query.columns[i];
		EN_MYSQL_FIELD_TYPE type = get_mysql_field_type(field.column_type.data());
		fprintf(fp, "\tDEFINE_MYSQL_ROW_FIELD(%s, %s);\n", field_2_str[type].data_type, field.column_name.data());
	}

	fprintf(fp, "\t%s_select_%s_row_t()\n", package.data(), query.tag.data());
	fprintf(fp, "\t{\n");
	fprintf(fp, "\t\tbzero(this, sizeof(%s_select_%s_row_t));\n", package.data(), query.tag.data());
	for(size_t i = 0; i < query.columns.size(); ++i){
		const t_field& field = query.columns[i];
		switch(get_mysql_field_type(field.column_type.data())){
			case EN_MYSQL_FIELD_STR:
			case EN_MYSQL_FIELD_VAR_STR:
			case EN_MYSQL_FIELD_BINARY:
				fprintf(fp, "\t\t%s = (char*)calloc(1, %d);\n", field.column_name.data(), field.column_max_len);
				fprintf(fp, "\t\t%s_len = %d;\n", field.column_name.data(), field.column_max_len);
				break;
			default:
				break;
		}
	}
	fprintf(fp, "\t}\n");

	fprintf(fp, "\t~%s_select_%s_row_t()\n", package.data(), query.tag.data());
	fprintf(fp, "\t{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		const t_field& field = query.columns[i];
		switch(get_mysql_field_type(field.column_type.data())){
			case EN_MYSQL_FIELD_STR:
			case EN_MYSQL_FIELD_BINARY:
				fprintf(fp, "\t\tfree(%s);\n", field.column_name.data());
				break;
			default:
				break;
		}
	}
	fprintf(fp, "\t}\n");
	fprintf(fp, "}%s_select_%s_row_t;\n", package.data(), query.tag.data());

	fprintf(fp, "int do_%s_select_%s(rpc_ctx_t* ctx, const mysql_selector_t& selector, %s_select_%s_condition_t& condition, std::vector<%s_select_%s_result_t>& results);\n\n", package.data(), query.tag.data(), package.data(), query.tag.data(), package.data(), query.tag.data());
}

void gen_insert_header(FILE* fp, const std::string& package, const t_mysql_query& query)
{
	fprintf(fp, "typedef struct %s_insert_%s_columns_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_field_in_member(fp, query.columns[i]);
	}
	fprintf(fp, "}%s_insert_%s_columns_t;\n", package.data(), query.tag.data());

	fprintf(fp, "typedef struct %s_insert_%s_update_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.updates.size(); ++i){
		fprintf_field_in_member(fp, query.updates[i]);
	}
	fprintf(fp, "}%s_insert_%s_update_t;\n", package.data(), query.tag.data());

	fprintf(fp, "int do_%s_insert_%s(rpc_ctx_t* ctx, const mysql_selector_t& selector, std::vector<%s_insert_%s_columns_t>& values, %s_insert_%s_update_t& update_duplicate_columns, int* affect_rows);\n\n", package.data(), query.tag.data(), package.data(), query.tag.data(), package.data(), query.tag.data());
}

void gen_update_header(FILE* fp, const std::string& package, const t_mysql_query& query)
{
	fprintf(fp, "typedef struct %s_update_%s_column_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_field_in_member(fp, query.columns[i]);
	}
	fprintf(fp, "}%s_update_%s_column_t;\n", package.data(), query.tag.data());

	fprintf(fp, "typedef struct %s_update_%s_condition_t\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	for(size_t i = 0; i < query.conditions.size(); ++i){
		fprintf_field_in_member(fp, query.conditions[i]);
	}
	fprintf(fp, "}%s_update_%s_condition_t;\n", package.data(), query.tag.data());

	fprintf(fp, "int do_%s_update_%s(rpc_ctx_t* ctx, const mysql_selector_t& selector, %s_update_%s_column_t& columns, %s_update_%s_condition_t& conditions, int* affect_rows);\n\n", package.data(), query.tag.data(), package.data(), query.tag.data(), package.data(), query.tag.data());
}

int gen_cc_file(const std::string& package, const std::vector<t_mysql_query>& querys, const char* out_dir)
{
	char sz_cc_file[1024];
	snprintf(sz_cc_file, sizeof(sz_cc_file), "%s/%s_mysql_orm.cc", out_dir, package.data());
	FILE* fp = fopen(sz_cc_file, "w");
	if(!fp){
		assert(0);
		printf("failed to open file:%s\n", sz_cc_file);
		return 1;
	}

	fprintf(fp, "#include \"%s_mysql_orm.h\"\n", package.data());
	fprintf(fp, "\n");

	for(size_t i = 0; i < querys.size(); ++i){
		const t_mysql_query& query = querys[i];
		switch(query.type){
			case EN_MYSQL_QUERY_SELECT:
				gen_select_cc(fp, package, query);
				break;
			case EN_MYSQL_QUERY_INSERT:
				gen_insert_cc(fp, package, query);
				break;
			case EN_MYSQL_QUERY_UPDATE:
				gen_update_cc(fp, package, query);
				break;
			default:
				break;
		}
	}
	fclose(fp);

	return 0;
}

static void fprintf_copy_field(FILE* fp, const t_field& field)
{
	EN_MYSQL_FIELD_TYPE type = get_mysql_field_type(field.column_type.data());
	switch(type){
		case EN_MYSQL_FIELD_STR:
		case EN_MYSQL_FIELD_VAR_STR:
		case EN_MYSQL_FIELD_BINARY:
			{
				fprintf(fp, "\trslt.%s = (char*)calloc(1, row->%s_len+1);\n", field.column_name.data(), field.column_name.data());
				fprintf(fp, "\trslt.%s_len = row->%s_len;\n", field.column_name.data(), field.column_name.data());
				fprintf(fp, "\tmemcpy(rslt.%s, row->%s, row->%s_len);\n", field.column_name.data(), field.column_name.data(), field.column_name.data());
			}
			break;
		default:
			fprintf(fp, "\trslt.%s = row->%s;\n", field.column_name.data(), field.column_name.data());
			break;
	}
}

static void fprintf_bind_condition(FILE* fp, const t_field& field, const char* indent, const char* name)
{
	EN_MYSQL_FIELD_TYPE type = get_mysql_field_type(field.column_type.data());
	switch(type){
		case EN_MYSQL_FIELD_STR:
		case EN_MYSQL_FIELD_VAR_STR:
		case EN_MYSQL_FIELD_BINARY:
			fprintf(fp, "%s%s(query, &%s.%s, &%s.%s_len);\n", indent, field_2_str[type].bind_param, name, field.column_name.data(), name, field.column_name.data());
			break;
		default:
			fprintf(fp, "%s%s(query, &%s.%s);\n", indent, field_2_str[type].bind_param, name, field.column_name.data());
			break;
	}
}

static void fprintf_bind_result(FILE* fp, const t_field& field)
{
	EN_MYSQL_FIELD_TYPE type = get_mysql_field_type(field.column_type.data());
	fprintf(fp, "\t%s(query, &row.%s, &row.is_%s_null, &row.%s_len, &row.is_%s_error);\n", field_2_str[type].bind_result, field.column_name.data(), field.column_name.data(), field.column_name.data(), field.column_name.data());
}

void gen_select_cc(FILE* fp, const std::string& package, const t_mysql_query& query)
{
	fprintf(fp, "static void fn_process_%s_select_%s_row(void* buff, void* ctx)\n", package.data(), query.tag.data());
	fprintf(fp, "{\n");
	fprintf(fp, "\t%s_select_%s_row_t* row = (%s_select_%s_row_t*)buff;\n", package.data(), query.tag.data(), package.data(), query.tag.data());
	fprintf(fp, "\tstd::vector<%s_select_%s_result_t>* results = (std::vector<%s_select_%s_result_t>*)ctx;\n", package.data(), query.tag.data(), package.data(), query.tag.data());
	fprintf(fp, "\tresults->push_back(%s_select_%s_result_t());\n", package.data(), query.tag.data());
	fprintf(fp, "\t%s_select_%s_result_t& rslt = results->back();\n", package.data(), query.tag.data());
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_copy_field(fp, query.columns[i]);
	}
	fprintf(fp, "}\n\n");

	fprintf(fp, "int do_%s_select_%s(rpc_ctx_t* ctx, const mysql_selector_t& selector, %s_select_%s_condition_t& conditions, std::vector<%s_select_%s_result_t>& results)\n", package.data(), query.tag.data(), package.data(), query.tag.data(), package.data(), query.tag.data());
	fprintf(fp, "{\n");
	if(!query.table.size()){
		fprintf(fp, "\tif(!selector.table){\n");
		fprintf(fp, "\t\tLOG_ERR(\"miss table\");\n");
		fprintf(fp, "\t\treturn EN_INVALID_DB_SELECTOR;\n");
		fprintf(fp, "\t}\n\n");
	}

	fprintf(fp, "\tMYSQL* mysql = selector.db_id?get_mysql_from_rpc_by_id(ctx, selector.db_id):get_mysql_from_rpc(ctx, selector.shard_key);\n");
	fprintf(fp, "\tif(!mysql){\n");
	fprintf(fp, "\t\tLOG_ERR(\"failed to get MYSQL inst. selector:%%s:%%llu\", selector.db_id?selector.db_id:\"NULL\", selector.shard_key);\n");
	fprintf(fp, "\t\treturn EN_INVALID_DB_SELECTOR;\n");
	fprintf(fp, "\t}\n");

	fprintf(fp, "\n\tchar sql[1024];\n");
	if(query.table.size()){
		fprintf(fp, "\tselector.table?snprintf(sql, sizeof(sql), \"%s\", selector.table):snprintf(sql, sizeof(sql), \"%s\", \"%s\");\n", query.sql.data(), query.sql.data(), query.table.data());
	}else{
		fprintf(fp, "\tsnprintf(sql, sizeof(sql), \"%s\", selector.table);\n", query.sql.data());
	}
	fprintf(fp, "\tmysql_query_t* query = mysql_malloc_query(ctx, mysql, sql);\n");
	for(size_t i = 0; i < query.conditions.size(); ++i){
		fprintf_bind_condition(fp, query.conditions[i], "\t", "conditions");
	}

	fprintf(fp, "\n\t%s_select_%s_row_t row;\n", package.data(), query.tag.data());
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_bind_result(fp, query.columns[i]);
	}

	fprintf(fp, "\n\tint rc = execute_mysql_query(query);\n");
	fprintf(fp, "\tif(rc){\n");
	fprintf(fp, "\t\tLOG_ERR(\"failed to query mysql:%%d:%%s:%%s\", rc, mysql_query_errmsg(query), sql);\n");
	fprintf(fp, "\t\tmysql_free_query(query);\n");
	fprintf(fp, "\t\treturn rc;\n");
	fprintf(fp, "\t}\n\n");

	fprintf(fp, "\tmysql_enumerate_rslt(query, fn_process_%s_select_%s_row, &row, &results);\n", package.data(), query.tag.data());
	fprintf(fp, "\tmysql_free_query(query);\n");
	fprintf(fp, "\treturn 0;\n");
	fprintf(fp, "}\n\n");
}

void gen_insert_cc(FILE* fp, const std::string& package, const t_mysql_query& query)
{
	fprintf(fp, "int do_%s_insert_%s(rpc_ctx_t* ctx, const mysql_selector_t& selector, std::vector<%s_insert_%s_columns_t>& values, %s_insert_%s_update_t& update_duplicate_columns, int* affect_rows)\n", package.data(), query.tag.data(), package.data(), query.tag.data(), package.data(), query.tag.data());
	fprintf(fp, "{\n");
	if(!query.table.size()){
		fprintf(fp, "\tif(!selector.table){\n");
		fprintf(fp, "\t\tLOG_ERR(\"miss table\");\n");
		fprintf(fp, "\t\treturn EN_INVALID_DB_SELECTOR;\n");
		fprintf(fp, "\t}\n\n");
	}

	fprintf(fp, "\tMYSQL* mysql = selector.db_id?get_mysql_from_rpc_by_id(ctx, selector.db_id):get_mysql_from_rpc(ctx, selector.shard_key);\n");
	fprintf(fp, "\tif(!mysql){\n");
	fprintf(fp, "\t\tLOG_ERR(\"failed to get MYSQL inst. selector:%%s:%%llu\", selector.db_id?selector.db_id:\"NULL\", selector.shard_key);\n");
	fprintf(fp, "\t\treturn EN_INVALID_DB_SELECTOR;\n");
	fprintf(fp, "\t}\n");

	fprintf(fp, "\n\tchar* sql_buff = NULL;\n");
	fprintf(fp, "\tsize_t sql_len = 0;\n");
	fprintf(fp, "\tif(values.size() > 1){\n");
	fprintf(fp, "\t\t//batch inserting\n");
	fprintf(fp, "\t\tif(!selector.table){\n");
	fprintf(fp, "\t\t\tLOG_ERR(\"MUST HAVE table when batch inserting\");\n");
	fprintf(fp, "\t\t\treturn EN_INVALID_DB_SELECTOR;\n");
	fprintf(fp, "\t\t}\n");

	fprintf(fp, "\n\t\tstd::string sql;\n");
	std::string sql = "INSERT INTO %s(";
	std::string placeholder = "(";
	for(size_t i = 0; i < query.columns.size(); ++i){
		placeholder.append("?");
		const t_field& field = query.columns[i];
		sql.append(field.column_name);
		if(i != query.columns.size() -1){
			placeholder.append(", ");
			sql.append(", ");
		}
	}
	sql.append(") VALUES");
	placeholder.append(")");
	fprintf(fp, "\t\tsql=\"%s\";\n", sql.data());
	fprintf(fp, "\t\tfor(size_t i = 0; i < values.size(); ++i){\n");
	fprintf(fp, "\t\t\tsql.append(\"%s\");\n", placeholder.data());
	fprintf(fp, "\t\t\tif(i != values.size() -1){\n");
	fprintf(fp, "\t\t\t\tsql.append(\",\");\n");
	fprintf(fp, "\t\t\t}\n");
	fprintf(fp, "\t\t}\n");
	const char* on_duplicate_key = strstr(query.sql.data(), "on duplicate key update");
	if(on_duplicate_key){
		fprintf(fp, "\t\tsql.append(\"%s\");\n", on_duplicate_key);
	}

	fprintf(fp, "\t\tsql_len = sql.size()+64;\n");
	fprintf(fp, "\t\tsql_buff = (char*)calloc(1, sql_len);\n");
	fprintf(fp, "\t\tsnprintf(sql_buff, sql_len, sql.data(), selector.table);\n");
	fprintf(fp, "\t}else{\n");
	fprintf(fp, "\t\tsql_buff = (char*)calloc(1, 1024);\n");
	fprintf(fp, "\t\tsql_len = 1024;\n");

	if(query.table.size()){
		fprintf(fp, "\t\tselector.table?snprintf(sql_buff, sql_len, \"%s\", selector.table):snprintf(sql_buff, sql_len, \"%s\", \"%s\");\n", query.sql.data(), query.sql.data(), query.table.data());
	}else{
		fprintf(fp, "\t\tsnprintf(sql_buff, sql_len, \"%s\", selector.table);\n", query.sql.data());
	}
	fprintf(fp, "\t}\n");

	fprintf(fp, "\n\tmysql_query_t* query = mysql_malloc_query(ctx, mysql, sql_buff);\n");
	fprintf(fp, "\tfor(size_t i = 0; i < values.size(); ++i){\n");
	fprintf(fp, "\t\t%s_insert_%s_columns_t& value = values[i];\n", package.data(), query.tag.data());
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_bind_condition(fp, query.columns[i], "\t\t", "value");
	}
	fprintf(fp, "\t}\n");

	for(size_t i = 0; i < query.updates.size(); ++i){
		fprintf_bind_condition(fp, query.updates[i], "\t", "update_duplicate_columns");
	}

	fprintf(fp, "\n\tint rc = execute_mysql_query(query);\n");
	fprintf(fp, "\tif(rc){\n");
	fprintf(fp, "\t\tLOG_ERR(\"failed to query mysql:%%d:%%s:%%s\", rc, mysql_query_errmsg(query), sql_buff);\n");
	fprintf(fp, "\t\tfree(sql_buff);\n");
	fprintf(fp, "\t\tmysql_free_query(query);\n");
	fprintf(fp, "\t\treturn rc;\n");
	fprintf(fp, "\t}\n\n");

	fprintf(fp, "\tfree(sql_buff);\n");
	fprintf(fp, "\tif(affect_rows){\n");
	fprintf(fp, "\t\t*affect_rows = mysql_affected_rows(query);\n");
	fprintf(fp, "\t}\n");

	fprintf(fp, "\tmysql_free_query(query);\n");
	fprintf(fp, "\treturn 0;\n");
	fprintf(fp, "}\n\n");
}

void gen_update_cc(FILE* fp, const std::string& package, const t_mysql_query& query)
{
	fprintf(fp, "int do_%s_update_%s(rpc_ctx_t* ctx, const mysql_selector_t& selector, %s_update_%s_column_t& columns, %s_update_%s_condition_t& conditions, int* affect_rows)\n", package.data(), query.tag.data(), package.data(), query.tag.data(), package.data(), query.tag.data());
	fprintf(fp, "{\n");
	if(!query.table.size()){
		fprintf(fp, "\tif(!selector.table){\n");
		fprintf(fp, "\t\tLOG_ERR(\"miss table\");\n");
		fprintf(fp, "\t\treturn EN_INVALID_DB_SELECTOR;\n");
		fprintf(fp, "\t}\n\n");
	}

	fprintf(fp, "\tMYSQL* mysql = selector.db_id?get_mysql_from_rpc_by_id(ctx, selector.db_id):get_mysql_from_rpc(ctx, selector.shard_key);\n");
	fprintf(fp, "\tif(!mysql){\n");
	fprintf(fp, "\t\tLOG_ERR(\"failed to get MYSQL inst. selector:%%s:%%llu\", selector.db_id?selector.db_id:\"NULL\", selector.shard_key);\n");
	fprintf(fp, "\t\treturn EN_INVALID_DB_SELECTOR;\n");
	fprintf(fp, "\t}\n");

	fprintf(fp, "\n\tchar sql[1024];\n");

	if(query.table.size()){
		fprintf(fp, "\t\tselector.table?snprintf(sql, sizeof(sql), \"%s\", selector.table):snprintf(sql, sizeof(sql), \"%s\", \"%s\");\n", query.sql.data(), query.sql.data(), query.table.data());
	}else{
		fprintf(fp, "\t\tsnprintf(sql, sizeof(sql), \"%s\", selector.table);\n", query.sql.data());
	}
	fprintf(fp, "\tmysql_query_t* query = mysql_malloc_query(ctx, mysql, sql);\n");
	for(size_t i = 0; i < query.columns.size(); ++i){
		fprintf_bind_condition(fp, query.columns[i], "\t", "columns");
	}

	for(size_t i = 0; i < query.conditions.size(); ++i){
		fprintf_bind_condition(fp, query.conditions[i], "\t", "conditions");
	}

	fprintf(fp, "\n\tint rc = execute_mysql_query(query);\n");
	fprintf(fp, "\tif(rc){\n");
	fprintf(fp, "\t\tLOG_ERR(\"failed to query mysql:%%d:%%s:%%s\", rc, mysql_query_errmsg(query), sql);\n");
	fprintf(fp, "\t\tmysql_free_query(query);\n");
	fprintf(fp, "\t\treturn rc;\n");
	fprintf(fp, "\t}\n\n");

	fprintf(fp, "\tif(affect_rows){\n");
	fprintf(fp, "\t\t*affect_rows = mysql_affected_rows(query);\n");
	fprintf(fp, "\t}\n");

	fprintf(fp, "\tmysql_free_query(query);\n");
	fprintf(fp, "\treturn 0;\n");
	fprintf(fp, "}\n\n");
}

void gen_orm_with_file(const char* filename, const char* out_dir)
{
	g_querys.clear();
	pquery = NULL;
	package = "";

	FILE* fp = fopen(filename, "r");
	if(!fp){
		printf("failed to open file:%s\n", filename);
		assert(0);
		return;
	}

	dup2(fileno(fp), STDIN_FILENO);
	yyparse();
	gen_mysql_orm_functions(package, g_querys, out_dir);
	fclose(fp);
}
