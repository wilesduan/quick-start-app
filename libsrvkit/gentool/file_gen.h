#ifndef __GEN_TOOL_FILE_GEN_H__
#define __GEN_TOOL_FILE_GEN_H__
#include <vector>

#include <proto.h>

void gen_src_with_proto(const proto_file_t* proto, const char* out_dir);
int do_mkdir(const char* mdir);
#endif//__GEN_TOOL_FILE_GEN_H__
