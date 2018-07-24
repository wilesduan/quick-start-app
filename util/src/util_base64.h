#ifndef _CLUSTER_UTIL_BASE_64_H
#define _CLUSTER_UTIL_BASE_64_H

#include <string>

void util_base64_encode(unsigned char const* , unsigned int len, std::string& str_enconde);
void util_base64_decode(std::string const& s, char* decode, size_t* decode_len);
#endif//_CLUSTER_UTIL_BASE_64_H

