%{
#include "orm_file_gen.h"
#include "y.tab.h"
#include <stdio.h>
#include <stdlib.h>
extern "C"{
int yywrap(void);
int yylex(void);
}
%}

%x _PACKAGE_
%x _PACKAGE_NAME_

%x _DEFINE_
%x _IN_DEFINE_
%x _IN_DEFINE_OP_TYPE_
%x _IN_DEFINE_OP_TAG_

%x _IN_DEFINE_SQL_
%x _IN_DEFINE_SQL_CONTENT_

%x _IN_DEFINE_TABLE_
%x _IN_DEFINE_TABLE_CONTENT_

%x _IN_DEFINE_COLUMN_
%x _IN_DEFINE_COLUMN_COLUMN_NAME_
%x _IN_DEFINE_COLUMN_COLUMN_TYPE_
%x _IN_DEFINE_COLUMN_COLUMN_TYPE_MAX_LEN_

%x _IN_DEFINE_CONDITION_
%x _IN_DEFINE_CONDITION_COLUMN_NAME_
%x _IN_DEFINE_CONDITION_COLUMN_TYPE_
%x _IN_DEFINE_CONDITION_COLUMN_TYPE_MAX_LEN_

%x _IN_DEFINE_UPDATE_
%x _IN_DEFINE_UPDATE_COLUMN_NAME_
%x _IN_DEFINE_UPDATE_COLUMN_TYPE_
%x _IN_DEFINE_UPDATE_COLUMN_TYPE_MAX_LEN_

%%
"#"[ \t]*"package" {
	BEGIN _PACKAGE_;
	return PACKAGE;
}

<_PACKAGE_>[a-zA-Z]+[-_a-zA-Z0-9]* {
	BEGIN _PACKAGE_NAME_;
	snprintf(yylval.package, sizeof(yylval.package), "%s", yytext);
	return PACKAGE_NAME;
}

<_PACKAGE_NAME_>"\n" {
	BEGIN INITIAL;
	return *yytext;
}

"#"[ \t]*"define" {
	BEGIN _DEFINE_;
	return DEFINE;
}

<_DEFINE_>"select" {
	BEGIN _IN_DEFINE_OP_TYPE_;
	yylval.type = EN_MYSQL_QUERY_SELECT;
	return IN_DEFINE_OP_TYPE;
}

<_DEFINE_>"insert" {
	BEGIN _IN_DEFINE_OP_TYPE_;
	yylval.type = EN_MYSQL_QUERY_INSERT;
	return IN_DEFINE_OP_TYPE;
}
<_DEFINE_>"update" {
	BEGIN _IN_DEFINE_OP_TYPE_;
	yylval.type = EN_MYSQL_QUERY_UPDATE;
	return IN_DEFINE_OP_TYPE;
}

<_IN_DEFINE_OP_TYPE_>[-_a-zA-Z0-9]+ {
	BEGIN _IN_DEFINE_OP_TAG_;
	snprintf(yylval.tag, sizeof(yylval.tag), "%s", yytext);
	return IN_DEFINE_OP_TAG;
}

<_IN_DEFINE_OP_TAG_>"\n" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_>"#"[ \t]*"sql" {
	BEGIN _IN_DEFINE_SQL_;
	return IN_DEFINE_SQL;
}

<_IN_DEFINE_SQL_>"{" {
	BEGIN _IN_DEFINE_SQL_CONTENT_;
	return *yytext;
}

<_IN_DEFINE_SQL_CONTENT_>[^}]* {
	snprintf(yylval.sql, sizeof(yylval.sql), "%s", yytext);
	return IN_DEFINE_SQL_CONTENT;
}

<_IN_DEFINE_SQL_CONTENT_>"}" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_>"#"[ \t]*"table" {
	BEGIN _IN_DEFINE_TABLE_;
	return IN_DEFINE_TABLE;
}

<_IN_DEFINE_TABLE_>"<" {
	BEGIN _IN_DEFINE_TABLE_CONTENT_;
	return *yytext;
}

<_IN_DEFINE_TABLE_CONTENT_>[^>]* {
	snprintf(yylval.table, sizeof(yylval.table), "%s", yytext);
	return IN_DEFINE_TABLE_CONTENT;
}

<_IN_DEFINE_TABLE_CONTENT_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_>"#"[ \t]*"column" {
	BEGIN _IN_DEFINE_COLUMN_;
	return IN_DEFINE_COLUMN;
}

<_IN_DEFINE_COLUMN_>[-_a-zA-Z0-9]+ {
	BEGIN _IN_DEFINE_COLUMN_COLUMN_NAME_;
	snprintf(yylval.column_name, sizeof(yylval.column_name), "%s", yytext);
	return IN_DEFINE_COLUMN_COLUMN_NAME;
}

<_IN_DEFINE_COLUMN_COLUMN_NAME_>"<" {
	BEGIN _IN_DEFINE_COLUMN_COLUMN_TYPE_;
	return *yytext;
}

<_IN_DEFINE_COLUMN_COLUMN_TYPE_>[^,>]* {
	snprintf(yylval.column_type, sizeof(yylval.column_type), "%s", yytext);
	return IN_DEFINE_COLUMN_COLUMN_TYPE;
}

<_IN_DEFINE_COLUMN_COLUMN_TYPE_>"," {
	BEGIN _IN_DEFINE_COLUMN_COLUMN_TYPE_MAX_LEN_;
	return *yytext;
}

<_IN_DEFINE_COLUMN_COLUMN_TYPE_MAX_LEN_>[^>]* {
	yylval.column_max_len = atoi(yytext);
	return IN_DEFINE_COLUMN_COLUMN_MAX_LEN;
}

<_IN_DEFINE_COLUMN_COLUMN_TYPE_MAX_LEN_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_COLUMN_COLUMN_TYPE_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_>"#"[ \t]*"condition" {
	BEGIN _IN_DEFINE_CONDITION_;
	return IN_DEFINE_CONDITION;
}

<_IN_DEFINE_CONDITION_>[-_a-zA-Z0-9]+ {
	BEGIN _IN_DEFINE_CONDITION_COLUMN_NAME_;
	snprintf(yylval.column_name, sizeof(yylval.column_name), "%s", yytext);
	return IN_DEFINE_CONDITION_COLUMN_NAME;
}

<_IN_DEFINE_CONDITION_COLUMN_NAME_>"<" {
	BEGIN _IN_DEFINE_CONDITION_COLUMN_TYPE_;
	return *yytext;
}

<_IN_DEFINE_CONDITION_COLUMN_TYPE_>[^,>]* {
	snprintf(yylval.column_type, sizeof(yylval.column_type), "%s", yytext);
	return IN_DEFINE_CONDITION_COLUMN_TYPE;
}

<_IN_DEFINE_CONDITION_COLUMN_TYPE_>"," {
	BEGIN _IN_DEFINE_CONDITION_COLUMN_TYPE_MAX_LEN_;
	return *yytext;
}

<_IN_DEFINE_CONDITION_COLUMN_TYPE_MAX_LEN_>[^>]* {
	yylval.column_max_len = atoi(yytext);
	return IN_DEFINE_CONDITION_COLUMN_MAX_LEN;
}

<_IN_DEFINE_CONDITION_COLUMN_TYPE_MAX_LEN_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_CONDITION_COLUMN_TYPE_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_>"#"[ \t]*"update" {
	BEGIN _IN_DEFINE_UPDATE_;
	return IN_DEFINE_UPDATE;
}

<_IN_DEFINE_UPDATE_>[-_a-zA-Z0-9]+ {
	BEGIN _IN_DEFINE_UPDATE_COLUMN_NAME_;
	snprintf(yylval.column_name, sizeof(yylval.column_name), "%s", yytext);
	return IN_DEFINE_UPDATE_COLUMN_NAME;
}

<_IN_DEFINE_UPDATE_COLUMN_NAME_>"<" {
	BEGIN _IN_DEFINE_UPDATE_COLUMN_TYPE_;
	return *yytext;
}

<_IN_DEFINE_UPDATE_COLUMN_TYPE_>[^,>]* {
	snprintf(yylval.column_type, sizeof(yylval.column_type), "%s", yytext);
	return IN_DEFINE_UPDATE_COLUMN_TYPE;
}

<_IN_DEFINE_UPDATE_COLUMN_TYPE_>"," {
	BEGIN _IN_DEFINE_UPDATE_COLUMN_TYPE_MAX_LEN_;
	return *yytext;
}

<_IN_DEFINE_UPDATE_COLUMN_TYPE_MAX_LEN_>[^>]* {
	yylval.column_max_len = atoi(yytext);
	return IN_DEFINE_UPDATE_COLUMN_MAX_LEN;
}

<_IN_DEFINE_UPDATE_COLUMN_TYPE_MAX_LEN_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_UPDATE_COLUMN_TYPE_>">" {
	BEGIN _IN_DEFINE_;
	return *yytext;
}

<_IN_DEFINE_>"#"[ \t]*"end" {
	BEGIN INITIAL;
	return DEFINE_END;
}

[ \t\n]  ;

%%
int yywrap(void)
{
return 1;
}
