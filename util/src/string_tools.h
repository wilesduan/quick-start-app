#ifndef STRING_TOOLS_H
#define STRING_TOOLS_H

#include <stdint.h>
#include <vector>
#include <string>

void implode(const std::string& source, const std::string& delimeter, std::vector<std::string>& values);
//-1表示解析失败；0表示整数, 1表示浮点
int parse_num(const char* src, int64_t& i_val, double& d_val);


#endif//STRING_TOOLS_H

