#include "string_tools.h"
#include <sstream>
#include <math.h>

void implode(const std::string& source, const std::string& delimeter, std::vector<std::string>& values)
{
	values.clear();

    size_t last = 0;
    size_t index = source.find_first_of(delimeter, last);
    while (index != std::string::npos)
    {
        values.push_back(source.substr(last, index-last));
        last = index + delimeter.size();
        index = source.find_first_of(delimeter,last);
    }
    if (index-last > 0)
    {
        values.push_back(source.substr(last,index-last));
    }
}


//-1表示解析失败；0表示整数, 1表示浮点
int parse_num(const char* src, int64_t& i_val, double& d_val)
{
    std::stringstream ss;
    ss << src;
    ss >> d_val;
    if (!ss || !ss.eof())
    {
        return -1;
    }

    i_val = int64_t(d_val);
    if (fabs(d_val - i_val) <= 1E-9) // 认为是相等
    {
       return 0;
    }
    else
    {
        return 1;
    }
}

