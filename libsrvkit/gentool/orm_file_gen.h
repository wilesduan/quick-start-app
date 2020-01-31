#ifndef _MYSQL_QUERY_HPP_
#define _MYSQL_QUERY_HPP_

#include <string>
#include <vector>

enum EN_MYSQL_QUERY_TYPE
{
	EN_MYSQL_QUERY_SELECT,
	EN_MYSQL_QUERY_INSERT,
	EN_MYSQL_QUERY_UPDATE,
};

enum EN_MYSQL_FIELD_TYPE
{
	EN_MYSQL_FIELD_TINY_INT = 0,
	EN_MYSQL_FIELD_INT32,
	EN_MYSQL_FIELD_INT64,
	EN_MYSQL_FIELD_UINT32,
	EN_MYSQL_FIELD_UINT64,
	EN_MYSQL_FIELD_FLOAT,
	EN_MYSQL_FIELD_DOUBLE,
	EN_MYSQL_FIELD_STR,
	EN_MYSQL_FIELD_VAR_STR,
	EN_MYSQL_FIELD_BINARY,

	EN_MYSQL_FIELD_LAST_ONE, //this type must be the last one
};

typedef struct field_2_str_t
{
	char data_type[16];
	char default_value[128];
	char bind_param[128];
	char bind_result[128];
}field_2_str_t;

typedef struct t_field
{
	std::string column_name;
	std::string column_type;
	int column_max_len;
}t_field;

typedef struct t_mysql_query
{
	EN_MYSQL_QUERY_TYPE type;
	std::string tag;
	std::string sql;
	std::string table;
	std::vector<t_field> columns;
	std::vector<t_field> conditions;
	std::vector<t_field> updates;
}t_mysql_query;

union uni_orm
{
	char package[128];
	EN_MYSQL_QUERY_TYPE type;
	char tag[128];
	char sql[1024];
	char table[128];
	char column_name[128];
	char column_type[128];
	int column_max_len;
};

extern "C"{
void gen_mysql_orm_functions(const std::string& package, const std::vector<t_mysql_query>& querys, const char* out_dir);
void gen_orm_with_file(const char* filename, const char* out_dir);
}
#define YYSTYPE uni_orm 

#endif//_MYSQL_QUERY_HPP_

