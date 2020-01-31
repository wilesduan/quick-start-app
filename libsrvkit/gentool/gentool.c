#include <unistd.h>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <proto.h>
#include <file_parser.h>
#include <file_gen.h>
#include <orm_file_gen.h>
#include <stdlib.h>

void usage(char* app)
{
	printf("%s -I path -f protofile -o output_dir -t [filetype: orm|proto]\n", app);
}

static void gen_proto_files(std::vector<char*>& path, char* file, char* out_dir);

#define K_FILE_TYPE_PROTO 1
#define K_FILE_TYPE_ORM 2
int get_file_type(char* ext, int default_type)
{
	if(!ext){
		return default_type;
	}

	if(strcmp(ext, ".orm") == 0){
		return K_FILE_TYPE_ORM;
	}

	if(strcmp(ext, ".proto") == 0){
		return K_FILE_TYPE_PROTO;
	}

	return default_type;
}

int main(int argc, char** argv)
{
	int c = 0;
	std::vector<char*> paths;
	paths.push_back(strdup("."));
	char* file_type = NULL;

	std::vector<char*> files;
	char* out_dir = strdup("./gentool_out");
	while(-1 != (c = getopt(argc, argv, 
				     "I:"//include path
					 "f:"//file
					 "o:"//output dir
					 "t:"//type[orm|proto]
					 "h" //show help
					))){
		switch(c){
			case 'I':
				{
					char* path = strdup(optarg);
					printf("include path:%s\n", path);
					paths.push_back(path);
					break;
				}
			case 'f':
				{
					char* proto_file = strdup(optarg);
					files.push_back(proto_file);
					printf("profofile: %s\n", proto_file);
					break;
				}
			case 'o':
				{
					free(out_dir);
					out_dir = strdup(optarg);
				}
				break;
			case 't':
				{
					file_type = strdup(optarg);
					break;
				}
			case 'h':
				usage(argv[0]);
				return 0;
		}
	}

	int ftype = K_FILE_TYPE_PROTO;
	if(file_type && strcmp(file_type, "orm") == 0){
		ftype = K_FILE_TYPE_ORM;
	}
	

	for(size_t i = 0; i < files.size(); ++i){
		char* filename = files[i];
		char* ext = strrchr(filename, '.');
		int type = get_file_type(ext, ftype);
		switch(type){
			case K_FILE_TYPE_PROTO:
				gen_proto_files(paths, filename, out_dir);
				break;
			case K_FILE_TYPE_ORM:
				gen_orm_with_file(filename, out_dir);
				break;
		}
	}

	return 0;
}

void gen_proto_files(std::vector<char*>& paths, char* file, char* out_dir)
{
	proto_file_t* proto = new proto_file_t;
	proto->file_name = strdup(file);
	parse_proto_file(paths, file, proto);

	if(proto->syntax){
		printf("%s", proto->syntax);
	}

	if(proto->package){
		printf("%s", proto->package);
	}

	for(size_t j = 0; j < proto->includes.size(); ++j){
		char* include = proto->includes[j];
		printf("import \"%s\"\n", include);
	}

	for(size_t j = 0; j < proto->messages.size(); ++j){
		proto_message_t& message = proto->messages[j];
		for(size_t k = 0; k < message.lines.size(); ++k){
			char* line = message.lines[k];
			printf("%s", line);
		}
	}

	for(size_t j = 0; j < proto->services.size(); ++j){
		proto_service_t& service = proto->services[j];
		printf("service name:%s\n", service.name);
		for(size_t k = 0; k < service.methods.size(); ++k){
			proto_method_t& method = service.methods[k];
			printf("rettype:%s\n", method.ret_type);
			printf("name:%s\n", method.name);
			printf("tag:%d\n", method.tag);
			printf("request type:%s, var_name:%s\n", method.req->type, method.req->name);
			if(method.rsp)
				printf("response type:%s, var_name:%s\n", method.rsp->type, method.rsp->name);
		}
	}

	gen_src_with_proto(proto, out_dir);
}

