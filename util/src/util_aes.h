#ifndef _BIM_UTIL_AES_H_
#define _BIM_UTIL_AES_H_ 

#include <stdint.h>

int util_aes_encrypt(const char* skey, const char* orig_stream, size_t length, char* enc_buff, size_t* enc_len);
int util_aes_decrypt(const char* skey, const char* enc_stream, size_t length, char* dec_buff, size_t* dec_len);
#endif //_AES_H_
