#ifndef __GEN_TOOL_FILE_PARSER_H__
#define __GEN_TOOL_FILE_PARSER_H__

#include <vector>
#include <proto.h>

enum parse_state
{
	en_state_start = 0,
	en_state_include = 1,
	en_state_package = 2,
	en_state_message = 3,
	en_state_service = 4,
	en_state_comment = 5,
	en_state_invalid = 6,
};

int parse_proto_file(std::vector<char*> paths, char* file, proto_file_t* proto);
#endif//__GEN_TOOL_FILE_PARSER_H__

