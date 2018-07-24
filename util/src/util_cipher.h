#ifndef _COMMON_CIPHER_TOOL_
#define _COMMON_CIPHER_TOOL_

#include <stdio.h>
#include <string>
#include <vector>
#include <util_buff.h>

#define K_PUBLIC_KEY_LEN 512 
#define K_PRIVATE_KEY_LEN 2048 

int generate_rsa_key_files();
int generate_rsa_key_mem(char public_key[K_PUBLIC_KEY_LEN], char private_key[K_PRIVATE_KEY_LEN]);

int test_rsa_keys(const char* public_key, const char* private_key);

int rsa_public_encrypt(const char* public_key, const char* szFrom, int total_len, std::string& encode);
int rsa_public_decrypt(const char* public_key, const std::string& encode, char* szbuff, size_t* buff_len);

int rsa_private_encrypt(const char* private_key, const char* szFrom, int total_len, std::string& encode);
int rsa_private_decrypt(const char* private_key, const std::string& encode, char* szbuff, size_t* buff_len);

int aes_encrypt_core(const unsigned char* key, const unsigned char* s, size_t s_len, char* enc_buff, size_t* enc_len);
int aes_decrypt_core(const unsigned char* key, const unsigned char* encode, size_t encode_len, unsigned char* d, size_t* d_len);

int aes_encrypt(const unsigned char* key, const unsigned char* s, size_t s_len, std::string& encode);
int aes_decrypt(const unsigned char* key, const std::string& encode, unsigned char* d, size_t* d_len);

int aes_encrypt_v(const unsigned char* key, std::vector<iovec>& iovs, char* encode, size_t* enc_len);
int aes_decrypt_v(const unsigned char* key, std::vector<iovec>& iovs, unsigned char* d, size_t* d_len);

int test_aes(const unsigned char* key);
#endif//_COMMON_CIPHER_TOOL_


