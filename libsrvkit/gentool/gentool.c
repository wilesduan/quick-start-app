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

static void gen_proto_files(std::vector<char*>& path, std::vector<char*>&files, char* out_dir);
static void gen_orm_files(std::vector<char*>&files, char* out_dir);

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

	if(file_type && strcmp(file_type, "orm") == 0){
		gen_orm_files(files, out_dir);
		return 0;
	}

	gen_proto_files(paths, files, out_dir);
	return 0;
}

void gen_proto_files(std::vector<char*>& paths, std::vector<char*>&files, char* out_dir)
{
	std::vector<proto_file_t*> protos;
	for(size_t i = 0; i < files.size(); ++i){
		proto_file_t* proto = new proto_file_t;
		proto->file_name = strdup(files[i]);
		parse_proto_file(paths, files[i], proto);
		protos.push_back(proto);
	}

	for(size_t i = 0; i < protos.size(); ++i){
		proto_file_t* proto = protos[i]; 
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
	}

	for(size_t i = 0; i < protos.size(); ++i){
		gen_src_with_proto(protos[i], out_dir);
	}
}

static void gen_orm_files(std::vector<char*>&files, char* out_dir)
{
	for(size_t i = 0; i < files.size(); ++i){
		char* filename = files[i];
		gen_orm_with_file(filename, out_dir);
	}
}
