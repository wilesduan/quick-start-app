#ifndef __GEN_TOOL_PROTO_H__
#define __GEN_TOOL_PROTO_H__

#include <vector>
#include <stdlib.h>

typedef struct proto_message_t
{
	char* name;
	std::vector<char*>lines;
	proto_message_t(){
		name = NULL;
	}
}proto_message_t;

typedef struct proto_var_t
{
	char* type;
	char* name;
	proto_var_t(){
		type = NULL;
		name = NULL;
	}
}proto_var_t;

enum method_sub_class
{
	en_sub_class_kafka = 1,
	en_sub_class_inner = 2
};

typedef struct proto_method_t
{
	char* ret_type;
	char* name;
	int sub_class;
	int tag;
	proto_var_t* req;
	proto_var_t* rsp;
	proto_method_t(){
		ret_type = NULL;
		name = NULL;
		req = NULL;
		rsp = NULL;
		sub_class = 0;
		tag = 0;
	}
}proto_method_t;

typedef struct proto_service_t
{
	char* name;
	std::vector<proto_method_t> methods;
	proto_service_t(){
		name = NULL;
	}
}proto_service_t;

typedef struct proto_file_t
{
	char* file_name;
	std::vector<char*> includes;
	char* package;
	char* syntax;
	std::vector<proto_message_t> messages;
	std::vector<proto_service_t> services;
	proto_file_t(){
		file_name = NULL;
		package = NULL;
		syntax = NULL;
	}
}proto_file_t;
#endif//__GEN_TOOL_PROTO_H__

