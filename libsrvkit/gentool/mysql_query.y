%{
#include <stdio.h>
#include <iostream>
#include "orm_file_gen.h"
#define YYDEBUG 0
extern "C"{
void yyerror(const char *s);
extern int yylex(void);
//extern void gen_mysql_orm_functions(const std::string& package, const std::vector<t_mysql_query>& querys);
}

std::vector<t_mysql_query> g_querys;
t_mysql_query* pquery = NULL;
std::string package;
%}


%token PACKAGE
%token PACKAGE_NAME

%token DEFINE
%token IN_DEFINE
%token IN_DEFINE_OP_TYPE
%token IN_DEFINE_OP_TAG

%token IN_DEFINE_SQL
%token IN_DEFINE_SQL_CONTENT

%token IN_DEFINE_TABLE
%token IN_DEFINE_TABLE_CONTENT

%token IN_DEFINE_COLUMN
%token IN_DEFINE_COLUMN_COLUMN_NAME
%token IN_DEFINE_COLUMN_COLUMN_TYPE
%token IN_DEFINE_COLUMN_COLUMN_MAX_LEN

%token IN_DEFINE_CONDITION
%token IN_DEFINE_CONDITION_COLUMN_NAME
%token IN_DEFINE_CONDITION_COLUMN_TYPE
%token IN_DEFINE_CONDITION_COLUMN_MAX_LEN

%token IN_DEFINE_UPDATE
%token IN_DEFINE_UPDATE_COLUMN_NAME
%token IN_DEFINE_UPDATE_COLUMN_TYPE
%token IN_DEFINE_UPDATE_COLUMN_MAX_LEN
%token DEFINE_END
%%
program:
       | program ORM_PROCESS
;

ORM_PROCESS:
		  PACKAGE PACKAGE_NAME '\n'
		  {
		      package = $2.package;
			  //printf("package:%s\n", $2.query);
		  }
          | DEFINE IN_DEFINE_OP_TYPE IN_DEFINE_OP_TAG '\n'
		  {
		      g_querys.push_back(t_mysql_query());
		      pquery = &g_querys.back();
			  pquery->type = $2.type;
			  pquery->tag = $3.tag;
			  //printf("define %d:%s\n", $2.type, $3.tag);
		  }
		  | IN_DEFINE_SQL '{' IN_DEFINE_SQL_CONTENT '}'
		  {
		      pquery->sql = $3.sql;
			  //printf("query:%s\n", $3.query);
		  }
		  | IN_DEFINE_TABLE '<' IN_DEFINE_TABLE_CONTENT '>'
		  {
		      pquery->table = $3.table;
		  }
		  | IN_DEFINE_COLUMN IN_DEFINE_COLUMN_COLUMN_NAME '<' IN_DEFINE_COLUMN_COLUMN_TYPE '>'
		  {
		      pquery->columns.push_back(t_field());
			  t_field* field = &(pquery->columns.back());
			  field->column_name = $2.column_name;
			  field->column_type = $4.column_type;
			  field->column_max_len = 0;
			  //printf("column %s:%s\n", $2.column_name, $4.column_type);
		  }
		  | IN_DEFINE_COLUMN IN_DEFINE_COLUMN_COLUMN_NAME '<' IN_DEFINE_COLUMN_COLUMN_TYPE ',' IN_DEFINE_COLUMN_COLUMN_MAX_LEN '>'
		  {
		      pquery->columns.push_back(t_field());
			  t_field* field = &(pquery->columns.back());
			  field->column_name = $2.column_name;
			  field->column_type = $4.column_type;
			  field->column_max_len = $6.column_max_len;
		  }
		  | IN_DEFINE_CONDITION IN_DEFINE_CONDITION_COLUMN_NAME '<' IN_DEFINE_CONDITION_COLUMN_TYPE '>'
		  {
		      pquery->conditions.push_back(t_field());
			  t_field* field = &(pquery->conditions.back());
			  field->column_name = $2.column_name;
			  field->column_type = $4.column_type;
			  field->column_max_len = 0;
			  //printf("condition %s:%s\n", $2.column_name, $4.column_type);
		  }
		  | IN_DEFINE_CONDITION IN_DEFINE_CONDITION_COLUMN_NAME '<' IN_DEFINE_CONDITION_COLUMN_TYPE ',' IN_DEFINE_CONDITION_COLUMN_MAX_LEN '>'
		  {
		      pquery->conditions.push_back(t_field());
			  t_field* field = &(pquery->conditions.back());
			  field->column_name = $2.column_name;
			  field->column_type = $4.column_type;
			  field->column_max_len = $6.column_max_len;
		  }
		  | IN_DEFINE_UPDATE IN_DEFINE_UPDATE_COLUMN_NAME '<' IN_DEFINE_UPDATE_COLUMN_TYPE '>'
		  {
		      pquery->updates.push_back(t_field());
			  t_field* field = &(pquery->updates.back());
			  field->column_name = $2.column_name;
			  field->column_type = $4.column_type;
			  field->column_max_len = 0;
			  //printf("update %s:%s\n", $2.column_name, $4.column_type);
		  }
		  | IN_DEFINE_UPDATE IN_DEFINE_UPDATE_COLUMN_NAME '<' IN_DEFINE_UPDATE_COLUMN_TYPE ',' IN_DEFINE_UPDATE_COLUMN_MAX_LEN '>'
		  {
		      pquery->updates.push_back(t_field());
			  t_field* field = &(pquery->updates.back());
			  field->column_name = $2.column_name;
			  field->column_type = $4.column_type;
			  field->column_max_len = $6.column_max_len;
		  }
		  | DEFINE_END
		  {
		  //printf("end\n");
		  }
%%


void yyerror(const char *s)
{
     //printf("error:");
     std::cerr<< s << std::endl;
}
/*
int main()
{
   yyparse();
   gen_mysql_orm_functions(package, g_querys);
   //std::copy(g_Includes.begin(),g_Includes.end(),std::ostream_iterator<Include>(std::cout,"\n"));
   return 0;
}
*/
