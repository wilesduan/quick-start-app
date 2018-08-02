#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <file_parser.h>

static void trim_line(char** line);
static void parse_new_line(char* line, enum parse_state* state, proto_file_t* proto);
static  void parse_import_line(char* token, proto_file_t* proto);
static  void parse_package_line(char* token, proto_file_t* proto);
static  void parse_message_line(char* token, enum parse_state* state, proto_file_t* proto);
static  void parse_service_line(char* token, enum parse_state* state, proto_file_t* proto);
static  void parse_comment_line(char* token, enum parse_state* state);
static proto_var_t* get_var_from_str(char* var);
static void move_util(char** line, char c);
static char* get_outter_name(char* line);

int g_line_num = 0;
char* g_line_content = NULL;
enum parse_state g_pre_state = en_state_invalid;

int parse_proto_file(std::vector<char*> paths, char* file, proto_file_t* proto)
{
	FILE* fp = fopen(file, "r");
	if(NULL == fp){
		printf("file not exist:%s\n", file);
		_exit(1);
	}

	enum parse_state state = en_state_start;

	const int size = 4096;
	char line[size];
	while(fgets(line, size, fp)){
		++g_line_num;
		char* ptr = line;
		trim_line(&ptr);

		if(*ptr == 0 || strncmp(ptr, "//", 2) == 0){
			if(state == en_state_message){
				proto_message_t& last = proto->messages.back();
				last.lines.push_back(strdup(line));
			}
			continue;
		}

		if(strncmp(ptr, "/*", 2) == 0){
			g_pre_state = state;
			state = en_state_comment;
			continue;
		}
		if(g_line_content){
			free(g_line_content);
		}

		g_line_content = strdup(line);

		switch(state){
			case en_state_start:
				{
					parse_new_line(ptr, &state, proto);
				}
				break;
			case en_state_message:
				{
					parse_message_line(ptr, &state, proto);
				}
				break;
			case en_state_service:
				{
					parse_service_line(ptr, &state, proto);
				}
				break;
			case en_state_comment:
				{
					parse_comment_line(ptr, &state);
				}
				break;
			default:
				break;
				
		}
	}

	return 0;
}

static void parse_new_line(char* line, enum parse_state* state, proto_file_t* proto)
{
	if(strncmp(line, "import ", 7) == 0){
	//if(strncmp(line, "#", 1) == 0 && strncmp(line+1, "include", 6) == 0){
		parse_import_line(line+7, proto);
		*state = en_state_start;
		return;
	}

	if(strncmp(line, "package", 7) == 0){
		parse_package_line(line+7, proto);
		*state = en_state_start;
		return;
	}

	if(strncmp(line, "message", 7) == 0){
		char* name = get_outter_name(line+7);
		if(NULL != name){
			proto->messages.push_back(proto_message_t());
			proto_message_t& last = proto->messages.back();
			last.name = name;
			last.lines.push_back(strdup(g_line_content));
			*state = en_state_message;
			return;
		}
		printf("invalid message line: %d:%s\n", g_line_num, g_line_content);
		exit(4);
	}

	if(strncmp(line, "enum", 4) == 0){
		char* name = get_outter_name(line+4);
		if(NULL != name){
			proto->messages.push_back(proto_message_t());
			proto_message_t& last = proto->messages.back();
			last.name = name;
			last.lines.push_back(strdup(g_line_content));
			*state = en_state_message;
			return;
		}
		printf("invalid enum line: %d:%s\n", g_line_num, g_line_content);
		exit(4);
	}

	if(strncmp(line, "service", 7) == 0){
		char* name = get_outter_name(line+7);
		if(NULL != name){
			proto->services.push_back(proto_service_t());
			proto_service_t& last = proto->services.back();
			last.name = name;
			*state = en_state_service;
			return;
		}

		printf("invalid service line: %d:%s\n", g_line_num, g_line_content);
		exit(5);
	}


	if(strncmp(line, "syntax", 6) == 0){
		proto->syntax = strdup(line);
		*state = en_state_start;
		return ;
	}

	printf("invalid line: %d:%s\n", g_line_num, g_line_content);
	exit(2);

	*state = en_state_invalid;
	return;
}

static void trim_line(char** line)
{
	char* p = *line;
	while(*p != 0 && (*p ==' ' || *p == '\n' || *p == '\t')){
		++p;
	}
	*line = p;
}

static  void parse_import_line(char* token, proto_file_t* proto)
{
	trim_line(&token);
	if(*token != '"'){
		printf("invalid import line: %d:%s\n", g_line_num, g_line_content);
		exit(99);
	}

	char* file = token+1;
	move_util(&file, '"');
	if(*file != '"'){
		printf("invalid import define:%d:%s", g_line_num, g_line_content);
		exit(100);
	}

	if(file - token -1 > 0){
		char* pf = strndup(token+1, file-token-1);
		proto->includes.push_back(pf);
	}
}

static  void parse_package_line(char* token, proto_file_t* proto)
{
	if(proto->package){
		printf("duplicate package. pre package:%s, package now:%s\n", proto->package, token);
		exit(3);
	}

	trim_line(&token);
	char* file = token;
	while(*file != 0 && *file != ' ' && *file != ';'){
		++file;
	}

	if(file - token > 0){
		char* pf = strndup(token, file-token);
		proto->package = pf;
	}
}

static  void parse_message_line(char* line, enum parse_state* state, proto_file_t* proto)
{
	proto_message_t& last = proto->messages.back();
	last.lines.push_back(strdup(g_line_content));
	trim_line(&line);
	if(*line == '}'){
		*state = en_state_start;
	}
}

static  void parse_service_line(char* pre_line, enum parse_state* state, proto_file_t* proto)
{
	char* line = pre_line;
	if(*line == '{'){
		return;
	}
	if(*line == '}'){
		*state = en_state_start;
		return;
	}

	proto_service_t& last = proto->services.back();
	last.methods.push_back(proto_method_t());
	proto_method_t& proto_method = last.methods.back();

	int offset = 0;
	if(strncmp(line, "int", 3) == 0){
		offset = 3;
	}else if(strncmp(line, "void", 4) == 0){
		offset = 4;
		strndup(line, offset);
	}else{
		printf("only int or void return type. unsupport return type:%d:%s\n", g_line_num, g_line_content);
		exit(6);
	}

	proto_method.ret_type = strndup(line, offset);
	line += offset;
	trim_line(&line);

	if(*line == '['){
	    char* att_p_end = line;
	    move_util(&att_p_end, ']');
	    char* sub_class_p = strndup(line+1 ,att_p_end-line-1);
	    
	    char* tmp_p = strtok(sub_class_p, ",");
	    while(tmp_p){
            if (!strncmp(tmp_p, "kafka", 6)){
                proto_method.sub_class |= en_sub_class_kafka;
            }
            if(!strncmp(tmp_p, "inner", 5)){
                proto_method.sub_class |= en_sub_class_inner;
            }
            tmp_p = strtok(NULL, ",");
	    }
        free(sub_class_p);
		move_util(&line, ']');
		++line;
	}

	char* method = line;
	while(*method != 0 && *method != ' ' && *method != '('){
		++method;
	}

	if(*method == 0){
		printf("invalid method line: %d:%s\n", g_line_num, g_line_content);
		exit(7);
	}

	proto_method.name = strndup(line, method-line);
	line = method;
	move_util(&line, '(');
	if(*line == 0){
		printf("invalid method line: %d:%s\n", g_line_num, g_line_content);
		exit(7);
	}

	++line;

	char* p = line;
	move_util(&p, ')');
	if(*p != ')'){
		printf("invalid method line: %d:%s\n", g_line_num, g_line_content);
		exit(8);
	}
	/*
	 * service example{
	 *    int do_hello(request ProtoRequest req, response ProtoResponse rsp) = 1;
	 * }
	 * 
	 */

	*p = 0;
	++p;
	move_util(&p, '=');
	if(*p == 0){
		printf("miss tag: %d:%s\n", g_line_num, g_line_content);
		exit(9);
	}

	++p;
	proto_method.tag = strtoul(p, NULL, 10);

	char* var = strtok(line, ",");
	trim_line(&var);
	if(strncmp(var, "request", 7) != 0){
		printf("miss request: %d:%s\n", g_line_num, g_line_content);
		exit(10);
	}

	proto_method.req = get_var_from_str(var+7);

	var = strtok(NULL, ",");
	if(var == NULL){
		proto_method.rsp = NULL;
		return;
	}

	trim_line(&var);
	if(strncmp(var, "response", 8) != 0){
		printf("invalid response: %d:%s\n", g_line_num, g_line_content);
		exit(11);
	}
	proto_method.rsp = get_var_from_str(var+8);
}

static proto_var_t* get_var_from_str(char* var)
{
	trim_line(&var);
	char* type = var;
	move_util(&var, ' ');

	if(*var == 0){
		printf("miss request:%s\n", var);
		exit(12);
	}

	type = strndup(type, var-type);
	trim_line(&var);
	char* name = var;
	move_util(&var, ' ');
	name = strndup(name, var-name);

	proto_var_t* proto_var = new proto_var_t();
	proto_var->type = type;
	proto_var->name = name;
	return proto_var;
}

static  void parse_comment_line(char* line, enum parse_state* state)
{
mark:
	move_util(&line, '*');
	if(*line == 0){
		return;
	}

	if(*line == '*' && *(line+1) == '/'){
		*state = (g_pre_state != en_state_invalid)?g_pre_state:en_state_start;
		return;
	}

	goto mark;
}

static void move_util(char** line, char c)
{
	char* p = *line;
	while(*p != 0 && *p != c){
		++p;
	}

	*line = p;
}

static char* get_outter_name(char* line)
{
	trim_line(&line);
	char* p = line;
	while(*p != 0 && (*p != ' ' && *p !='{' && *p != '\t' && *p != '\n')){
		++p;
	}

	return strndup(line, p-line);
}
