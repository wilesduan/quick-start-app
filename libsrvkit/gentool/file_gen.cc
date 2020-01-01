#include <file_gen.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

static int gen_proto_content(const proto_file_t* proto, const char* sz_proto_dir);
static int gen_cli_content(const proto_file_t* proto, const proto_service_t* service, const char* sz_cli_dir);
static int gen_srv_content(const proto_file_t* proto, const proto_service_t* service, const char* sz_srv_dir);
static char* get_file_name_ex_proto(const char* name);

static int do_mkdir(const char* mdir)
{
	int rc = 0;
	DIR* dir = opendir(mdir);
	if(NULL == dir){
		rc = mkdir(mdir, 0777);
		if(rc){
			printf("failed to mkdir:%s\n", mdir);
		}
	}else{
		closedir(dir);
	}

	return rc;
}

static void gen_srv_main_file(const proto_file_t* proto, const char* sz_srv_dir)
{
	char sz_filename[1024];
	strncpy(sz_filename, proto->file_name, sizeof(sz_filename));
	char* filename = strchr(basename(sz_filename), '.');
	if(filename) *filename = 0;
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/%s.cc", sz_srv_dir, sz_filename);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}

	fprintf(fp, "\n");
	fprintf(fp, "#include <server.h>\n");
	for(size_t i = 0; i < proto->services.size(); ++i){
		fprintf(fp, "#include <proto_%s_%s.h>\n", proto->package, proto->services[i].name);
	}
	fprintf(fp, "\n");

	fprintf(fp, "int main(int argc, char** argv)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "    server_t* server = malloc_server(argc, argv);\n");
	fprintf(fp, "    if(NULL == server){\n");
	fprintf(fp, "        return 0;\n");
	fprintf(fp, "    }\n\n");
	for(size_t i = 0; i < proto->services.size(); ++i){
		fprintf(fp, "    add_service(server, gen_%s_%s_service());\n", proto->package, proto->services[i].name);
	}
	fprintf(fp, "\n");

	fprintf(fp, "    run_server(server);\n");
	fprintf(fp, "    return 0;\n");
	fprintf(fp, "}");

}

void gen_src_with_proto(const proto_file_t* proto, const char* out_dir)
{
	if(NULL == out_dir){
		printf("ERROR miss out dir\n");
		return;
	}


	if(strlen(out_dir) > 512){
		printf("too long out dir:%s\n", out_dir);
		return;
	}

	int rc = do_mkdir(out_dir);
	char sz_proto_dir[1024];
	char sz_cli_dir[1024];
	char sz_srv_dir[1024];

	snprintf(sz_proto_dir, sizeof(sz_proto_dir), "%s/%s", out_dir, "gen_proto");
	rc = do_mkdir(sz_proto_dir);
	if(rc){
		printf("failed to mkdir: %s\n", sz_proto_dir);
		return;
	}

	snprintf(sz_cli_dir, sizeof(sz_cli_dir), "%s/%s", out_dir, "gen_cli");
	rc = do_mkdir(sz_cli_dir);
	if(rc){
		printf("failed to mkdir: %s\n", sz_cli_dir);
		return;
	}

	snprintf(sz_srv_dir, sizeof(sz_srv_dir), "%s/%s", out_dir, "gen_srv");
	rc = do_mkdir(sz_srv_dir);
	if(rc){
		printf("failed to mkdir: %s\n", sz_cli_dir);
		return;
	}

	rc = gen_proto_content(proto, sz_proto_dir);
	if(rc){
		return;
	}

	for(size_t i = 0; i < proto->services.size(); ++i){
		rc = gen_cli_content(proto, &(proto->services[i]), sz_cli_dir);
		if(rc){
			return;
		}

		rc = gen_srv_content(proto, &(proto->services[i]), sz_srv_dir);
		if(rc){
			return;
		}

	}

	if(proto->services.size()){
		gen_srv_main_file(proto, sz_srv_dir);
	}
}

static int gen_proto_content(const proto_file_t* proto, const char* sz_proto_dir)
{
	char sz_file_name[1024];
	if(strlen(sz_proto_dir) + strlen(proto->file_name) + strlen("gen_")+1 > 1023){
		printf("too long file:%s/gen_%s\n", sz_proto_dir, proto->file_name);
		return -1;
	}

	snprintf(sz_file_name, sizeof(sz_file_name), "%s/gen_%s", sz_proto_dir, proto->file_name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s", sz_file_name);
		return -2;
	}

	if(proto->syntax){
		fprintf(fp, "%s\n", proto->syntax);
	}

	for(size_t i = 0; i < proto->includes.size(); ++i){
		fprintf(fp, "import \"%s\";\n", proto->includes[i]);
	}
	fprintf(fp, "\n");

	if(proto->package){
		fprintf(fp, "package %s;\n", proto->package);
	}
	fprintf(fp, "\n");

	for(size_t i = 0; i < proto->messages.size(); ++i){
		const proto_message_t& message = proto->messages[i];
		for(size_t j = 0; j < message.lines.size(); ++j){
			fprintf(fp, "%s", message.lines[j]);
		}
		fprintf(fp, "\n");
	}

	fclose(fp);

	/*
	char cwd[512];
	getcwd(cwd,sizeof(cwd));
	size_t len = snprintf(sz_file_name, sizeof(sz_file_name), "%s/protoc --cpp_out=. -I . ", cwd);
	for(size_t i = 0; i < proto->includes.size(); ++i){
		len  += snprintf(sz_file_name+len, sizeof(sz_file_name)-len, "-I %s ", proto->includes[i]);
	}
	snprintf(sz_file_name+len, sizeof(sz_file_name)-len, "%s/gen_%s;", sz_proto_dir, proto->file_name);
	printf("command: %s\n", sz_file_name);

	FILE* stream = popen(sz_file_name, "r");
	if(NULL == stream){
		printf("failed to gen proto file\n");
		return -2;
	}

	char tmp[512];
	while(fgets(tmp, sizeof(tmp)-1, stream) != NULL){
		tmp[sizeof(tmp)-1] = 0;
		printf("%s", tmp);
	}
	printf("\n");
	pclose(stream);
	*/

	return 0;
}

static void gen_cli_header_code(const proto_file_t* proto, const proto_service_t* service, const char* sz_cli_dir)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/proto_%s_%s_cli.h", sz_cli_dir, proto->package, service->name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}

	fprintf(fp, "#ifndef __LIB_SERVICE_%s_%s_PROTO_CLI_H__\n", proto->package, service->name);
	fprintf(fp, "#define __LIB_SERVICE_%s_%s_PROTO_CLI_H__\n", proto->package, service->name);
	fprintf(fp, "\n");

	for(size_t i = 0; i < proto->includes.size(); ++i){
		char* filename = get_file_name_ex_proto(proto->includes[i]);
		fprintf(fp, "#include <%s.pb.h>\n", filename);
		free(filename);
	}

	char* filename = get_file_name_ex_proto(proto->file_name);
	fprintf(fp, "#include <gen_%s.pb.h>\n", filename);
	free(filename);
	fprintf(fp, "#include <server.h>\n");
	fprintf(fp, "#include <string>\n");
	fprintf(fp, "\n\n");

	char req_type[256];
	char rsp_type[256];
	for(size_t i = 0; i < service->methods.size(); ++i){
		const proto_method_t& method = service->methods[i];
		if(strstr(method.req->type, "::") == NULL){
			snprintf(req_type, sizeof(req_type), "%s::%s", proto->package, method.req->type);
		}else{
			snprintf(req_type, sizeof(req_type), "%s", method.req->type);
		}

		if(method.rsp && strstr(method.rsp->type, "::") == NULL){
			snprintf(rsp_type, sizeof(rsp_type), "%s::%s", proto->package, method.rsp->type);
		}else if(method.rsp){
			snprintf(rsp_type, sizeof(rsp_type), "%s", method.rsp->type);
		}

		char sz_ctrl[1024];
		snprintf(sz_ctrl, sizeof(sz_ctrl), "%s", method.name);
		char* p = sz_ctrl;
		while(*p != '\0'){
			if(*p == '.')
				*p = '_';
			++p;
		}

		if(method.rsp){
			fprintf(fp, "int call_pb_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, %s* %s, int timeout=0);\n", proto->package, service->name, sz_ctrl, req_type, method.req->name, rsp_type, method.rsp->name);
			fprintf(fp, "int call_swoole_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, %s* %s, int version=1, int timeout=0);\n", proto->package, service->name, sz_ctrl, req_type, method.req->name, rsp_type, method.rsp->name);
		}else{
			fprintf(fp, "int call_pb_%s_%s_%s(rpc_ctx_t* ctx, %s* %s);\n", proto->package, service->name, sz_ctrl, req_type, method.req->name);
			fprintf(fp, "int call_swoole_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, int version=1);\n", proto->package,service->name, sz_ctrl, req_type, method.req->name);
		}

		if(method.sub_class&en_sub_class_kafka){
			fprintf(fp, "int gen_kafka_pb_msg_%s_%s(rpc_ctx_t* ctx, %s* %s, std::string& str_pb_kafka_msg);\n", service->name, sz_ctrl,req_type, method.req->name);
			fprintf(fp, "int gen_kafka_js_msg_%s_%s(rpc_ctx_t* ctx, %s* %s, std::string& str_json_kafka_msg);\n", service->name, sz_ctrl, req_type, method.req->name);
		}
	}
	fprintf(fp, "\n");

	fprintf(fp, "#endif//__LIB_SERVICE_%s_%s_PROTO_CLI_H__\n", proto->package, service->name);
}

static void gen_cli_cc_code(const proto_file_t* proto, const proto_service_t* service, const char* sz_cli_dir)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/proto_%s_%s_cli.cc", sz_cli_dir, proto->package, service->name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}

	fprintf(fp, "#include <proto_%s_%s_cli.h>\n", proto->package, service->name);
	fprintf(fp, "#include <bim_util.h>\n");
	fprintf(fp, "#include <json.h>\n");
	fprintf(fp, "#include <blink.pb.h>\n\n");
	char req_type[256];
	char rsp_type[256];
	for(size_t i = 0; i < service->methods.size(); ++i){
		const proto_method_t& method = service->methods[i];
		if(strstr(method.req->type, "::") == NULL){
			snprintf(req_type, sizeof(req_type), "%s::%s", proto->package, method.req->type);
		}else{
			snprintf(req_type, sizeof(req_type), "%s", method.req->type);
		}

		if(method.rsp && strstr(method.rsp->type, "::") == NULL){
			snprintf(rsp_type, sizeof(rsp_type), "%s::%s", proto->package, method.rsp->type);
		}else if(method.rsp){
			snprintf(rsp_type, sizeof(rsp_type), "%s", method.rsp->type);
		}

		char sz_ctrl[1024];
		snprintf(sz_ctrl, sizeof(sz_ctrl), "%s", method.name);
		char* p = sz_ctrl;
		while(*p != '\0'){
			if(*p == '.')
				*p = '_';
			++p;
		}
		//////////////////////////////////////pb/////////////////////////////
		if(method.rsp){
			fprintf(fp, "int call_pb_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, %s* %s, int timeout)\n", proto->package, service->name, sz_ctrl, req_type, method.req->name, rsp_type, method.rsp->name);
		}else{
			fprintf(fp, "int call_pb_%s_%s_%s(rpc_ctx_t* ctx, %s* %s)\n", proto->package, service->name, sz_ctrl, req_type, method.req->name);
		}

		fprintf(fp, "{\n");
		if(!method.rsp){
			fprintf(fp, "\tctx->co->wait_reply = 0;\n");
		}else{
			fprintf(fp, "\tctx->co->wait_reply = 1;\n");
		}
		fprintf(fp, "\tchar sz_mon_key[100];\n");
		fprintf(fp, "\tsz_mon_key[99] = 0;\n");
		if(method.rsp){
		    fprintf(fp, "\tint rc = async_req_with_pb_msg((worker_thread_t*)ctx->co->worker, ctx->co, \"%s\", %d, %s, timeout);\n", service->name, method.tag, method.req->name);
        }
        else{
            fprintf(fp, "\tint rc = async_req_with_pb_msg((worker_thread_t*)ctx->co->worker, ctx->co, \"%s\", %d, %s);\n", service->name, method.tag, method.req->name);
        }
		fprintf(fp, "\tif(rc){\n");
		fprintf(fp, "\t\tregist_rpc_info(&(ctx->co->rpc_info), \"%s\", \"%s\");\n", service->name, method.name);
		fprintf(fp, "\t\tmc_collect((worker_thread_t*)ctx->co->worker, &(ctx->co->rpc_info), 0, rc, 0, ctx->co->uctx.ss_trace_id_s);\n");
		fprintf(fp, "\t\tLOG_ERR(\"[%s_ALARM][%s]@call %s::%s failed. rc:%%d, trace_id:%%s, uid:%%llu\", rc, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);\n", service->name, method.name, service->name, method.name);
		fprintf(fp, "\t\tsnprintf(sz_mon_key, 99, \"async_req_%%s_%%s_errcode_%%d\", \"%s\", \"%s\", rc);\n", service->name, method.name);
		fprintf(fp, "\t\tMONITOR_ACC(sz_mon_key, 1);\n");
		fprintf(fp,"\t\treturn rc;\n\t}\n\n");
		if(!method.rsp){
			fprintf(fp, "\treturn rc;\n");
		}else{
			fprintf(fp, "\tif(is_co_in_batch_mode(ctx->co)){\n");
			fprintf(fp, "\t\tbatch_rpc_result_t* last_rslt = get_co_last_req_rslt(ctx->co);\n");
			fprintf(fp, "\t\tlast_rslt->rsp = %s;\n", method.rsp->name);
			fprintf(fp, "\t\tregist_rpc_info(&(last_rslt->rpc_info), \"%s\", \"%s\");\n", service->name, method.name);
			fprintf(fp, "\t\treturn 0;\n");
			fprintf(fp, "\t}\n\n");

			fprintf(fp, "\tregist_rpc_info(&(ctx->co->rpc_info), \"%s\", \"%s\");\n", service->name, method.name);
			fprintf(fp, "\tadd_co_timeout_wheel((worker_thread_t*)(ctx->co->worker), ctx->co);\n");
			fprintf(fp, "\tBEGIN_CALC_RPC_COST();\n");
			fprintf(fp, "\tco_yield(ctx->co);\n");
			fprintf(fp, "\tEND_CALC_RPC_COST(\"%s\", \"%s\", ctx->co->uctx.ss_trace_id_s);\n\n", service->name, method.name);
			fprintf(fp, "\tif(ctx->co->sys_code){\n");
			fprintf(fp, "\t\tsnprintf(sz_mon_key, 99, \"call_%%s_%%s_errcode_%%d\", \"%s\", \"%s\", ctx->co->sys_code);\n", service->name, method.name);
			fprintf(fp, "\t\tMONITOR_ACC(sz_mon_key, 1);\n");
			fprintf(fp, "\t\tLOG_ERR(\"[%s_ALARM][%s]@return code:%%d, trace_id:%%s, uid:%%llu\", ctx->co->sys_code, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);\n", service->name, method.name);

			fprintf(fp, "\t\treturn ctx->co->sys_code;\n\t}\n\n");
			fprintf(fp, "\tbool parse = %s->ParseFromArray(ctx->co->params, ctx->co->size);\n", method.rsp->name);
			fprintf(fp, "\tif(!parse){\n");
			fprintf(fp, "\t\tsnprintf(sz_mon_key, 99, \"call_%%s_%%s_parse_err\", \"%s\", \"%s\");\n", service->name, method.name);
			fprintf(fp, "\t\tMONITOR_ACC(sz_mon_key, 1);\n");
			fprintf(fp, "\t\tLOG_ERR(\"[%s][%s]failed to parse reponse of type:%s, trace_id:%%s\", ctx->co->uctx.ss_trace_id_s);\n", service->name, method.name, rsp_type);
			fprintf(fp, "\t\treturn blink::EN_MSG_RET_PARSE_ERR;\n");
			fprintf(fp, "\t}\n");
			fprintf(fp, "\treturn 0;\n");
		}
		fprintf(fp, "}\n\n");
		//////////////////////////////////////swoole/////////////////////////////

		if(method.rsp){
			fprintf(fp, "int call_swoole_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, %s* %s, int version, int timeout)\n", proto->package, service->name, sz_ctrl, req_type, method.req->name, rsp_type, method.rsp->name);
		}else{
			fprintf(fp, "int call_swoole_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, int version)\n", proto->package, service->name, sz_ctrl, req_type, method.req->name);
		}

		fprintf(fp, "{\n");
		if(!method.rsp){
			fprintf(fp, "\tctx->co->wait_reply = 0;\n");
		}else{
			fprintf(fp, "\tctx->co->wait_reply = 1;\n");
		}

		fprintf(fp, "\tchar sz_mon_key[100];\n");
		fprintf(fp, "\tsz_mon_key[99] = 0;\n");
		if(method.rsp){
    		fprintf(fp, "\tint rc = async_req_with_swoole_msg((worker_thread_t*)ctx->co->worker, ctx->co, \"%s\", \"%s\", %s, version, timeout);\n", service->name, method.name, method.req->name);
        }
        else{
            fprintf(fp, "\tint rc = async_req_with_swoole_msg((worker_thread_t*)ctx->co->worker, ctx->co, \"%s\", \"%s\", %s, version);\n", service->name, method.name, method.req->name);
        }
		fprintf(fp, "\tif(rc){\n");
		fprintf(fp, "\t\tregist_rpc_info(&(ctx->co->rpc_info), \"%s\", \"%s\");\n", service->name, method.name);
		fprintf(fp, "\t\tmc_collect((worker_thread_t*)ctx->co->worker, &(ctx->co->rpc_info), 0, rc, 0, ctx->co->uctx.ss_trace_id_s);\n");
		fprintf(fp, "\t\tsnprintf(sz_mon_key, 99, \"async_req_%%s_%%s_errcode_%%d\", \"%s\", \"%s\", rc);\n", service->name, method.name);
		fprintf(fp, "\t\tMONITOR_ACC(sz_mon_key, 1);\n");
		fprintf(fp, "\t\tLOG_ERR(\"[%s_ALARM][%s]@call %s::%s failed. rc:%%d, trace_id:%%s, uid:%%llu\", rc, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);\n", service->name, method.name, service->name, method.name);
		fprintf(fp,"\t\treturn rc;\n\t}\n\n");
		if(!method.rsp){
			fprintf(fp, "\treturn rc;\n");
		}else{
			fprintf(fp, "\tif(is_co_in_batch_mode(ctx->co)){\n");
			fprintf(fp, "\t\tbatch_rpc_result_t* last_rslt = get_co_last_req_rslt(ctx->co);\n");
			fprintf(fp, "\t\tlast_rslt->rsp = %s;\n", method.rsp->name);
			fprintf(fp, "\t\tregist_rpc_info(&(last_rslt->rpc_info), \"%s\", \"%s\");\n", service->name, method.name);
			fprintf(fp, "\t\treturn 0;\n");
			fprintf(fp, "\t}\n\n");

			fprintf(fp, "\tregist_rpc_info(&(ctx->co->rpc_info), \"%s\", \"%s\");\n", service->name, method.name);
			fprintf(fp, "\tadd_co_timeout_wheel((worker_thread_t*)(ctx->co->worker), ctx->co);\n");
			fprintf(fp, "\tBEGIN_CALC_RPC_COST();\n");
			fprintf(fp, "\tco_yield(ctx->co);\n");
			fprintf(fp, "\tEND_CALC_RPC_COST(\"%s\", \"%s\", ctx->co->uctx.ss_trace_id_s);\n\n", service->name, method.name);
			fprintf(fp, "\tif(ctx->co->sys_code){\n");
			fprintf(fp, "\t\tLOG_ERR(\"[%s_ALARM][%s]@return code:%%d, trace_id:%%s, uid:%%llu\", ctx->co->sys_code, ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);\n", service->name, method.name);

			fprintf(fp, "\t\tsnprintf(sz_mon_key, 99, \"call_%%s_%%s_errcode_%%d\", \"%s\", \"%s\", ctx->co->sys_code);\n", service->name, method.name);
			fprintf(fp, "\t\tMONITOR_ACC(sz_mon_key, 1);\n");

			fprintf(fp, "\t\treturn ctx->co->sys_code;\n\t}\n\n");
			fprintf(fp, "\trc = util_parse_pb_from_json(%s, (json_object*)(ctx->co->json_swoole_body_data));\n", method.rsp->name);
			fprintf(fp, "\tif(rc){\n");
			fprintf(fp, "\t\tsnprintf(sz_mon_key, 99, \"call_%%s_%%s_parse_err\", \"%s\", \"%s\");\n", service->name, method.name);
			fprintf(fp, "\t\tMONITOR_ACC(sz_mon_key, 1);\n");
			fprintf(fp, "\t\tLOG_ERR(\"[%s_ALARM][%s]@failed to parse reponse of type:%s from json, trace_id:%%s, uid:%%llu\", ctx->co->uctx.ss_trace_id_s, ctx->co->uctx.uid);\n", service->name, method.name, rsp_type);
			fprintf(fp, "\t\treturn blink::EN_MSG_RET_PARSE_ERR;\n");
			fprintf(fp, "\t}\n");
			fprintf(fp, "\treturn 0;\n");
		}
		fprintf(fp, "}\n\n");

		
		if(method.sub_class & en_sub_class_kafka){
			fprintf(fp, "int gen_kafka_pb_msg_%s_%s(rpc_ctx_t* ctx, %s* %s, std::string& str_pb_kafka_msg)\n{\n", service->name, sz_ctrl, req_type, method.req->name);
			fprintf(fp, "\tblink::MsgBody body;\n");
			fprintf(fp, "\tbody.set_call_type(blink::EN_MSG_TYPE_REQUEST);\n");
			fprintf(fp, "\tif(ctx->co->proto_user_ctx) body.mutable_uctx()->CopyFrom(*((blink::UserContext*)ctx->co->proto_user_ctx));\n");
			fprintf(fp, "\tbody.set_service(\"%s\");\n", service->name);
			fprintf(fp, "\tbody.set_method(%d);\n", method.tag);
			fprintf(fp, "\tstd::string tmp_payload;\n");
			fprintf(fp, "\treq->SerializeToString(&tmp_payload);\n");
			fprintf(fp, "\tbody.set_payload(tmp_payload);\n");
			fprintf(fp, "\tbody.SerializeToString(&str_pb_kafka_msg);\n");
			fprintf(fp, "\treturn 0;\n");
			fprintf(fp, "}\n\n");
			fprintf(fp, "int gen_kafka_json_msg_%s_%s(rpc_ctx_t* ctx, %s* %s, std::string& str_json_kafka_msg)\n{\n", service->name, sz_ctrl, req_type, method.req->name);
			fprintf(fp, "\t//TODO\n");
			fprintf(fp, "\treturn 0;\n");
			fprintf(fp, "}\n\n");
		}
	}
}

static int gen_cli_content(const proto_file_t* proto, const proto_service_t* service, const char* sz_cli_dir)
{
	if(strlen(sz_cli_dir) + strlen(proto->file_name) + strlen("gen_")+1 > 1023){
		printf("too long file:%s/gen_%s\n", sz_cli_dir, proto->file_name);
		return -1;
	}

	gen_cli_header_code(proto, service, sz_cli_dir);
	gen_cli_cc_code(proto, service, sz_cli_dir);
	return 0;
}

static char* get_file_name_ex_proto(const char* name)
{
	char* tmp = strdup(name);
	for(size_t i = strlen(tmp)-1; i > 0; --i){
		if(*(tmp+i) == '.'){
			if(strcmp(tmp+i, ".proto") == 0){
				*(tmp+i) = 0;
				return tmp;
			}
			break;
		}
	}

	return tmp;
}

static void gen_srv_imp_header_file(const proto_file_t* proto, const proto_service_t* service, const char* sz_srv_dir)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/proto_%s_%s_imp.h", sz_srv_dir, proto->package, service->name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}

	fprintf(fp, "#ifndef __LIB_SERVICE_%s_%s_IMP_PROTO_H__\n", proto->package, service->name);
	fprintf(fp, "#define __LIB_SERVICE_%s_%s_IMP_PROTO_H__\n", proto->package, service->name);
	for(size_t i = 0; i < proto->includes.size(); ++i){
		char* filename = get_file_name_ex_proto(proto->includes[i]);
		fprintf(fp, "#include <%s.pb.h>\n", filename);
		free(filename);
	}

	char* filename = get_file_name_ex_proto(proto->file_name);
	fprintf(fp, "#include <gen_%s.pb.h>\n", filename);
	free(filename);
	fprintf(fp, "#include <server.h>\n");
	fprintf(fp, "\n\n");

	char req_type[256];
	char rsp_type[256];
	for(size_t i = 0; i < service->methods.size(); ++i){
		const proto_method_t& method = service->methods[i];
		if(strstr(method.req->type, "::") == NULL){
			snprintf(req_type, sizeof(req_type), "%s::%s", proto->package, method.req->type);
		}else{
			snprintf(req_type, sizeof(req_type), "%s", method.req->type);
		}

		if(method.rsp){
			if(strstr(method.rsp->type, "::") == NULL){
				snprintf(rsp_type, sizeof(rsp_type), "%s::%s", proto->package, method.rsp->type);
			}else{
				snprintf(rsp_type, sizeof(rsp_type), "%s", method.rsp->type);
			}

			fprintf(fp, "int do_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, %s* %s);\n",proto->package, service->name, method.name, req_type, method.req->name, rsp_type, method.rsp->name);
		}else{
			fprintf(fp, "int do_%s_%s_%s(rpc_ctx_t* ctx, %s* %s);\n", proto->package, service->name, method.name, req_type, method.req->name);
		}

	}
	fprintf(fp, "\n");

	fprintf(fp, "#endif//__LIB_SERVICE_%s_%s_IMP_PROTO_H__\n", proto->package, service->name);
	fclose(fp);
}

static void gen_srv_imp_cc_file(const proto_file_t* proto, const proto_service_t* service, const char* sz_srv_dir)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/proto_%s_%s_imp.cc", sz_srv_dir, proto->package, service->name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}
	fprintf(fp, "#include <proto_%s_%s_imp.h>\n", proto->package, service->name);
	fprintf(fp, "\n\n");

	char req_type[256];
	char rsp_type[256];
	for(size_t i = 0; i < service->methods.size(); ++i){
		const proto_method_t& method = service->methods[i];
		if(strstr(method.req->type, "::") == NULL){
			snprintf(req_type, sizeof(req_type), "%s::%s", proto->package, method.req->type);
		}else{
			snprintf(req_type, sizeof(req_type), "%s", method.req->type);
		}

		if(method.rsp){
			if(strstr(method.rsp->type, "::") == NULL){
				snprintf(rsp_type, sizeof(rsp_type), "%s::%s", proto->package, method.rsp->type);
			}else{
				snprintf(rsp_type, sizeof(rsp_type), "%s", method.rsp->type);
			}
			fprintf(fp, "int do_%s_%s_%s(rpc_ctx_t* ctx, %s* %s, %s* %s)\n", proto->package, service->name, method.name, req_type, method.req->name, rsp_type, method.rsp->name);
			fprintf(fp, "{\n\t//TODO\n\treturn 0;\n}\n\n");
		}else{
			fprintf(fp, "int do_%s_%s_%s(rpc_ctx_t* ctx, %s* %s)\n",proto->package, service->name,  method.name, req_type, method.req->name);
			fprintf(fp, "{\n\t//TODO\n\treturn 0;\n}\n\n");
		}
	}

	fclose(fp);
}

static void gen_srv_header_file(const proto_file_t* proto, const proto_service_t* service, const char* sz_srv_dir)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/proto_%s_%s.h", sz_srv_dir, proto->package, service->name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}

	fprintf(fp, "#ifndef __LIB_SERVICE_%s_%s_PROTO_H__\n", proto->package, service->name);
	fprintf(fp, "#define __LIB_SERVICE_%s_%s_PROTO_H__\n", proto->package, service->name);
	fprintf(fp, "\n");

	fprintf(fp, "#include <server.h>\n");
	fprintf(fp, "\n\n");

	fprintf(fp, "service_t* gen_%s_%s_service();\n", proto->package, service->name);
	fprintf(fp, "\n");
	fprintf(fp, "#endif//__LIB_SERVICE_%s_%s_IMP_PROTO_H__\n", proto->package, service->name);
	fprintf(fp, "\n");
	fclose(fp);
}

static void gen_srv_cc_file(const proto_file_t* proto, const proto_service_t* service, const char* sz_srv_dir)
{
	char sz_file_name[1024];
	snprintf(sz_file_name, sizeof(sz_file_name), "%s/proto_%s_%s.cc", sz_srv_dir, proto->package, service->name);

	FILE* fp = fopen(sz_file_name, "w");
	if(NULL == fp){
		printf("failed to open file:%s\n", sz_file_name);
		return;
	}

	fprintf(fp, "#include <proto_%s_%s.h>\n", proto->package, service->name);
	fprintf(fp, "#include <proto_%s_%s_imp.h>\n", proto->package, service->name);
	fprintf(fp, "#include <bim_util.h>\n");
	char* filename = get_file_name_ex_proto(proto->file_name);
	fprintf(fp, "#include <gen_%s.pb.h>\n", filename);
	fprintf(fp, "#include <blink.pb.h>\n");
	fprintf(fp, "#include <json.h>\n");
	fprintf(fp, "#include <string>\n");
	fprintf(fp, "#include <sys/time.h>\n");
    fprintf(fp, "#include <swoole_def.h>\n");
    
	fprintf(fp, "\n"); 
	int max_tag = 0;
	for(size_t i = 0; i < service->methods.size(); ++i){
		const proto_method_t& method = service->methods[i];
		if(method.tag > max_tag) max_tag = method.tag;

		//////////////////////pb reuest///////////////////////////
		fprintf(fp, "static int fn_pb_%s_%s(ev_ptr_t* ptr, coroutine_t* co)\n", service->name, method.name);
		fprintf(fp, "{\n");
		char* req_type = method.req->type;
		fprintf(fp, "\t");
		if(strstr(req_type, "::") == NULL){
			fprintf(fp, "%s::%s* %s = new %s::%s();\n", proto->package, req_type, method.req->name, proto->package, req_type);
		}else{
			fprintf(fp, "%s* %s = new %s();\n", req_type, method.req->name, req_type);
		}

		if(method.rsp){
			char* rsp_type = method.rsp->type;
			fprintf(fp, "\t");
			if(strstr(rsp_type, "::") == NULL){
				fprintf(fp, "%s::%s* %s = new %s::%s();\n", proto->package, rsp_type, method.rsp->name, proto->package, rsp_type);
			}else{
				fprintf(fp, "%s* %s = new %s();\n", rsp_type, method.rsp->name, rsp_type);
			}
		}
        
		fprintf(fp, "\trpc_ctx_t ctx;\n");
		fprintf(fp, "\tctx.ptr= ptr;\n");
		fprintf(fp, "\tctx.co = co;\n");

		fprintf(fp, "\tadd_trace_point(&ctx, \"%s\", \"%s\", \"\", 0);\n", service->name, method.name);
		fprintf(fp, "\tbool parse = %s->ParseFromArray(co->params, co->size);\n", method.req->name);
		fprintf(fp, "\tif(!parse){\n\t\tLOG_ERR(\"[%s][%s]failed to parse request %s, trace_id:%%s uid:%%llu\", co->uctx.ss_trace_id_s, co->uctx.uid);\n", service->name, method.name, method.req->name);
		if(method.rsp){
			fprintf(fp, "\t\tack_req_with_rsp(ptr, co, blink::EN_MSG_RET_PARSE_ERR, %s);\n", method.rsp->name);
			fprintf(fp, "\t\tdelete %s;\n", method.rsp->name);
		}
		fprintf(fp, "\t\tdelete %s;\n\t\treturn -1;\n\t}", method.req->name);

		fprintf(fp, "\n\n\tMONITOR_ACC(\"qpm_pb_%s\", 1);", method.name);
		if(method.rsp){
			fprintf(fp, "\n");
			fprintf(fp, "\tstruct timeval start_tv, end_tv;\n");
			fprintf(fp, "\tgettimeofday(&start_tv,NULL);\n");
			fprintf(fp, "\tint rc = do_%s_%s_%s(&ctx, %s, %s);\n", proto->package, service->name, method.name, method.req->name, method.rsp->name);
			fprintf(fp, "\tgettimeofday(&end_tv,NULL);\n");
			fprintf(fp, "\tuint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;\n");
			fprintf(fp, "\tLOG_INFO(\"#BLINK_NOTICE#[%s@%s|%%s|%%ums|%%d|%%llu|%%d|%%u][%%s][%%s]\", co->uctx.ss_trace_id_s, cost, rc, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), %s->ShortDebugString().data(), %s->ShortDebugString().data());\n", service->name, method.name, method.req->name, method.rsp->name);
			fprintf(fp, "\trefill_trace_point(&ctx, \"%s\", \"%s\", cost, rc);\n", service->name, method.name);
			fprintf(fp, "\tack_req_with_rsp(ptr, co, rc, %s);\n", method.rsp->name);
			fprintf(fp, "\tdelete %s;\n", method.rsp->name);
		}else{
			fprintf(fp, "\n");
			fprintf(fp, "\n\tstruct timeval start_tv, end_tv;\n");
			fprintf(fp, "\tgettimeofday(&start_tv,NULL);\n");
			fprintf(fp, "\tdo_%s_%s_%s(&ctx, %s);\n", proto->package, service->name, method.name, method.req->name);
			fprintf(fp, "\tgettimeofday(&end_tv,NULL);\n");
			fprintf(fp, "\tuint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;\n");
			fprintf(fp, "\trefill_trace_point(&ctx, \"%s\", \"%s\", cost, 0);\n", service->name, method.name);
			fprintf(fp, "\tLOG_INFO(\"#BLINK_NOTICE#[%s@%s|%%s|%%ums|0|%%llu|%%d|%%u][%%s]\", co->uctx.ss_trace_id_s, cost, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), %s->ShortDebugString().data());\n", service->name, method.name, method.req->name);
		}
		fprintf(fp, "\tdelete %s;\n", method.req->name);
		fprintf(fp, "\treturn 0;\n}\n\n");

		//////////////////////swoole reuest///////////////////////////
		fprintf(fp, "static int fn_swoole_%s_%s(ev_ptr_t* ptr, coroutine_t* co)\n", service->name, method.name);
		fprintf(fp, "{\n");
		fprintf(fp, "\t");
		if(strstr(req_type, "::") == NULL){
			fprintf(fp, "%s::%s* %s = new %s::%s();\n", proto->package, req_type, method.req->name, proto->package, req_type);
		}else{
			fprintf(fp, "%s* %s = new %s();\n", req_type, method.req->name, req_type);
		}

		if(method.rsp){
			char* rsp_type = method.rsp->type;
			fprintf(fp, "\t");
			if(strstr(rsp_type, "::") == NULL){
				fprintf(fp, "%s::%s* %s = new %s::%s();\n", proto->package, rsp_type, method.rsp->name, proto->package, rsp_type);
			}else{
				fprintf(fp, "%s* %s = new %s();\n", rsp_type, method.rsp->name, rsp_type);
			}
		}
		if (method.sub_class& en_sub_class_inner){
			fprintf(fp, "\tswoole_head* head = (swoole_head*)co->swoole_head;\n");
			fprintf(fp, "\tif (head->header_reserved == 1){\n");
			fprintf(fp, "\t\tblink::SwooleHttp swoole_http;\n");
			fprintf(fp, "\t\tint ret = util_parse_pb_from_json(&swoole_http, (json_object*)(co->json_swoole_body_http));\n");
			fprintf(fp, "\t\tif (ret){\n");
			if(method.rsp){
    			fprintf(fp, "\t\t\tack_req_with_rsp(ptr, co, blink::EN_MSG_RET_PARSE_ERR, rsp);\n");
                fprintf(fp, "\t\t\tdelete rsp;\n");
    	    }
			fprintf(fp, "\t\t\tdelete req;\n");
			fprintf(fp, "\t\t\treturn -1;\n");
			fprintf(fp, "\t\t}\n");
			fprintf(fp, "\t\tconst char* last_char = swoole_http.header().host().c_str() + swoole_http.header().host().size() - 1;\n");
			fprintf(fp, "\t\tif (!(*last_char == 'o' && head->header_version == 0)){\n");
			if(method.rsp){
                fprintf(fp, "\t\t\tack_req_with_rsp(ptr, co, blink::EN_MSG_ERT_METHOD_LIMIT, rsp);\n");
                fprintf(fp, "\t\t\tdelete rsp;\n");
    	    }
			fprintf(fp, "\t\t\tdelete req;\n");
			fprintf(fp, "\t\t\treturn -1;\n");
			fprintf(fp, "\t\t}\n");
			fprintf(fp, "\t}\n");
			fprintf(fp, "\n");
 		}
		
		fprintf(fp, "\trpc_ctx_t ctx;\n");
		fprintf(fp, "\tctx.ptr= ptr;\n");
		fprintf(fp, "\tctx.co = co;\n");

		fprintf(fp, "\tadd_trace_point(&ctx, \"%s\", \"%s\", \"\", 0);\n", service->name, method.name);
		fprintf(fp, "\tint rc = util_parse_pb_from_json(%s, (json_object*)(co->json_swoole_body_body));\n", method.req->name);
		fprintf(fp, "\tif(rc){\n\t\tLOG_ERR(\"[%s_ALARM][%s]@failed to parse request %s, trace_id:%%s uid:%%llu\", co->uctx.ss_trace_id_s, co->uctx.uid);\n", service->name, method.name, method.req->name);
		if(method.rsp){
			fprintf(fp, "\t\tack_req_with_rsp(ptr, co, blink::EN_MSG_RET_PARSE_ERR, %s);\n", method.rsp->name);
			fprintf(fp, "\t\tdelete %s;\n", method.rsp->name);
		}
		fprintf(fp, "\t\tdelete %s;\n\t\treturn -1;\n\t}", method.req->name);

		fprintf(fp, "\n\n\tMONITOR_ACC(\"qpm_swoole_%s\", 1);", method.name);
		if(method.rsp){
	        fprintf(fp, "\n");
			fprintf(fp, "\tstruct timeval start_tv, end_tv;\n");
			fprintf(fp, "\tgettimeofday(&start_tv,NULL);\n");
			fprintf(fp, "\trc = do_%s_%s_%s(&ctx, %s, %s);\n", proto->package, service->name, method.name, method.req->name, method.rsp->name);
			fprintf(fp, "\tgettimeofday(&end_tv,NULL);\n");
			fprintf(fp, "\tuint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;\n");
			fprintf(fp, "\tLOG_INFO(\"#BLINK_NOTICE#[%s@%s|%%s|%%ums|%%d|%%llu|%%d|%%u][%%s][%%s]\", co->uctx.ss_trace_id_s, cost, rc, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), %s->ShortDebugString().data(), %s->ShortDebugString().data());\n", service->name, method.name, method.req->name, method.rsp->name);
			fprintf(fp, "\trefill_trace_point(&ctx, \"%s\", \"%s\", cost, rc);\n", service->name, method.name);
			fprintf(fp, "\tack_req_with_rsp(ptr, co, rc, %s);\n", method.rsp->name);
			fprintf(fp, "\tdelete %s;\n", method.rsp->name);
		}else{
			fprintf(fp, "\n\n");
			fprintf(fp, "\tstruct timeval start_tv, end_tv;\n");
			fprintf(fp, "\tgettimeofday(&start_tv,NULL);\n");
			fprintf(fp, "\tdo_%s_%s_%s(&ctx, %s);\n", proto->package, service->name, method.name, method.req->name);
			fprintf(fp, "\tgettimeofday(&end_tv,NULL);\n");
			fprintf(fp, "\tuint32_t cost = 1000 * (end_tv.tv_sec - start_tv.tv_sec) + (end_tv.tv_usec - start_tv.tv_usec)  / 1000;\n");
			fprintf(fp, "\trefill_trace_point(&ctx, \"%s\", \"%s\", cost);\n", service->name, method.name);
			fprintf(fp, "\tLOG_INFO(\"#BLINK_NOTICE#[%s@%s|%%s|%%ums|0|%%llu|%%d|%%u][%%s]\", co->uctx.ss_trace_id_s, cost, co->uctx.uid, co->uctx.dev_type, (unsigned)(co->uctx.dev_crc32), %s->ShortDebugString().data());\n", service->name, method.name, method.req->name);
		}
		fprintf(fp, "\tdelete %s;\n", method.req->name);
		fprintf(fp, "\treturn 0;\n}\n\n");
	}

	if(max_tag == 0){
		max_tag = 1;
	}

	fprintf(fp, "service_t* gen_%s_%s_service()\n{\n", proto->package, service->name);
	fprintf(fp, "\tservice_t* service = (service_t*)calloc(1, sizeof(service_t));\n");
	fprintf(fp, "\tif(NULL == service){\n\t\tLOG_ERR(\"[%s_ALARM][%s]@failed to alloc mem for service:%s\");\n\t\treturn NULL;\n\t}\n", service->name, service->name, service->name);
	fprintf(fp, "\n");
    fprintf(fp, "\tINIT_LIST_HEAD(&service->list);\n");
	fprintf(fp, "\tservice->name = strdup(\"%s\");\n", service->name);
	fprintf(fp, "\tservice->num_methods= %d;\n", max_tag);
	fprintf(fp, "\tservice->methods = (fn_method*)calloc(%d, sizeof(fn_method));\n", max_tag+1);
	fprintf(fp, "\tservice->swoole_meth = (swoole_method_t*)calloc(%lu, sizeof(swoole_method_t));\n", service->methods.size());
	for(size_t i = 0; i < service->methods.size(); ++i){
		fprintf(fp, "\tservice->methods[%d] = fn_pb_%s_%s;\n\n", service->methods[i].tag,service->name, service->methods[i].name);

		fprintf(fp, "\tservice->swoole_meth[%d].method = fn_swoole_%s_%s;\n", (int)i,service->name, service->methods[i].name);
		fprintf(fp, "\tservice->swoole_meth[%d].method_name = strdup(\"%s\");\n", (int)i, service->methods[i].name);

		if(service->methods[i].database){
			fprintf(fp, "\tservice->swoole_meth[%d].database = strdup(\"%s\");\n", (int)i, service->methods[i].database);
		}

		if(service->methods[i].table){
			fprintf(fp, "\tservice->swoole_meth[%d].table = strdup(\"%s\");\n", (int)i, service->methods[i].table);
		}

		if(service->methods[i].type){
			fprintf(fp, "\tservice->swoole_meth[%d].type = strdup(\"%s\");\n", (int)i, service->methods[i].type);
		}
	}
	fprintf(fp, "\treturn service;\n}\n");
    
	fclose(fp);
}


static int gen_srv_content(const proto_file_t* proto, const proto_service_t* service, const char* sz_srv_dir)
{
	if(strlen(sz_srv_dir) + strlen(service->name) + strlen("proto_") > 1000){
		printf("too long file:%s/proto_%s_%s_srv.h\n", sz_srv_dir, proto->package, service->name);
		return -1;
	}

	gen_srv_imp_header_file(proto, service, sz_srv_dir);
	gen_srv_imp_cc_file(proto, service, sz_srv_dir);

	gen_srv_header_file(proto, service, sz_srv_dir);
	gen_srv_cc_file(proto, service, sz_srv_dir);
	return 0;
}
