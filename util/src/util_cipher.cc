#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/aes.h>

#include <string.h>
#include "util_md5.h"
#include "util_cipher.h"
#include "util_base64.h"
#include <util_buff.h>

int generate_rsa_key_files()
{
	int ret = 0;
	RSA *rsa = NULL;
	BIGNUM *bne = NULL;
	BIO *bp_public = NULL, *bp_private = NULL;

	int bits = 2048;
	unsigned long   e = RSA_F4;
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	rsa = RSA_new();
	ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	bp_public = BIO_new_file("public.pem", "w");
	ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
	if(ret != 1)
	{
		goto free_all;
	}

	bp_private = BIO_new_file("private.pem", "w");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
	//iRet = PEM_write_bio_RSAPrivateKey(pBp, pRsa, EVP_des_ede3(), (unsigned char*)passwd, 4, NULL, NULL);
	if(ret != 1)
	{
		goto free_all;
	}

free_all:
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bne);

	return (ret == 1);
}

int generate_rsa_key_mem(char public_key[K_PUBLIC_KEY_LEN], char private_key[K_PRIVATE_KEY_LEN])
{
	int ret = 0;
	RSA *rsa = NULL;
	BIGNUM *bne = NULL;
	BIO *bp_public = NULL, *bp_private = NULL;
	size_t size;

	int bits = 1024;
	unsigned long   e = RSA_F4;
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	rsa = RSA_new();
	ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	bp_public = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
	if(ret != 1)
	{
		goto free_all;
	}

	size = BIO_ctrl_pending(bp_public);
	if(size < K_PUBLIC_KEY_LEN)
	{
		BIO_read(bp_public, public_key, size);
	}
	else
		ret = -1;

	bp_private = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
	//iRet = PEM_write_bio_RSAPrivateKey(pBp, pRsa, EVP_des_ede3(), (unsigned char*)passwd, 4, NULL, NULL);
	if(ret != 1)
	{
		goto free_all;
	}

	size = BIO_ctrl_pending(bp_private);
	if(size < K_PRIVATE_KEY_LEN)
	{
		BIO_read(bp_private, private_key, size);
	}
	else
		ret = -1;

free_all:
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bne);

	return ret;
}

int rsa_public_encrypt(const char* public_key, const char* from, int total_len, std::string& encode)
{
	if(NULL == public_key || NULL == from)
	{
		return -1;
	}

	int rc = 0;
	int len = 0;
	int enc_len = 0;
	unsigned char* buff = NULL;

    RSA* pRsa = NULL;
	BIO* pBp = BIO_new(BIO_s_mem());
	BIO_puts(pBp, public_key);
	pRsa = PEM_read_bio_RSAPublicKey(pBp, NULL, NULL, NULL );
	if(NULL == pRsa)
	{
		rc = -1;
		goto free_bio;
	}

	enc_len = RSA_size(pRsa);
	buff = (unsigned char*)malloc((total_len+enc_len)/enc_len*enc_len);
	if(NULL == buff){
		goto free_rsa;
	}

	while(len < total_len)
	{
		rc = RSA_public_encrypt(enc_len, (unsigned char*)from+len, buff + len, pRsa, RSA_NO_PADDING);
		if(rc < 0)
		{
			rc = -2;
			goto free_buff;
		}
		len += rc;
	}

	util_base64_encode(buff, len, encode);

	rc = 0;
free_buff:
	free(buff);
free_rsa:
	RSA_free(pRsa);
free_bio:
	BIO_free_all(pBp);

	return rc;
}

int rsa_public_decrypt(const char* pszPrivateKey, const std::string& encode, char* szbuff, size_t* buff_len)
{
	if(NULL == szbuff || NULL == buff_len)
	{
		return 0;
	}

	if(NULL == pszPrivateKey)
	{
		return -1;
	}

	char* base64_decode = (char*)malloc(encode.size());
	if(NULL == base64_decode){
		return -2;
	}

	size_t encode_len = encode.size();
	util_base64_decode(encode, base64_decode, &encode_len);

    RSA* pRsa = NULL;
	BIO* pBp = BIO_new(BIO_s_mem());
	BIO_puts(pBp, pszPrivateKey);

	int rc = 0;
	int len = 0;
	int enc_len = 0;
	pRsa = PEM_read_bio_RSAPublicKey(pBp, NULL, NULL, NULL);
	if(NULL == pRsa)
	{
		rc = -3;
		goto free_bio;
	}

	enc_len = RSA_size(pRsa);

	while(len < (int)encode_len)
	{
		rc = RSA_public_decrypt(enc_len, (unsigned char*)base64_decode+len, (unsigned char*)szbuff+len, pRsa, RSA_NO_PADDING);
		if(rc < 0)
		{
			rc = -4;
			goto free_rsa;
		}

		len += rc;
	}

	rc = 0;
	*buff_len = len;

free_rsa:
	RSA_free(pRsa);
free_bio:
	BIO_free_all(pBp);
	free(base64_decode);
	return rc;
}

int rsa_private_decrypt(const char* pszPrivateKey, const std::string& encode, char* szbuff, size_t* buff_len)
{
	if(NULL == szbuff || NULL == buff_len)
	{
		return 0;
	}

	if(NULL == pszPrivateKey)
	{
		return -1;
	}

	char* base64_decode = (char*)malloc(encode.size());
	if(NULL == base64_decode){
		return -2;
	}

	size_t encode_len = encode.size();
	util_base64_decode(encode, base64_decode, &encode_len);

    RSA* pRsa = NULL;
	BIO* pBp = BIO_new(BIO_s_mem());
	BIO_puts(pBp, pszPrivateKey);

	int rc = 0;
	int len = 0;
	int enc_len = 0;
	pRsa = PEM_read_bio_RSAPrivateKey(pBp, NULL, NULL, NULL);
	if(NULL == pRsa)
	{
		rc = -3;
		goto free_bio;
	}

	enc_len = RSA_size(pRsa);
	while(len < (int)encode_len)
	{
		rc = RSA_private_decrypt(enc_len, (unsigned char*)base64_decode+len, (unsigned char*)szbuff+len, pRsa, RSA_NO_PADDING);
		if(rc < 0)
		{
			rc = -4;
			goto free_rsa;
		}

		len += rc;
	}

	rc = 0;
	*buff_len = len;

free_rsa:
	RSA_free(pRsa);
free_bio:
	BIO_free_all(pBp);
	free(base64_decode);
	return rc;
}

int rsa_private_encrypt(const char* public_key, const char* from, int total_len, std::string& encode)
{
	if(NULL == public_key || NULL == from)
	{
		return -1;
	}

	int rc = 0;
	int len = 0;
	int enc_len = 0;
	unsigned char* buff = NULL;

    RSA* pRsa = NULL;
	BIO* pBp = BIO_new(BIO_s_mem());
	BIO_puts(pBp, public_key);
	pRsa = PEM_read_bio_RSAPrivateKey(pBp, NULL, NULL, NULL );
	if(NULL == pRsa)
	{
		rc = -1;
		goto free_bio;
	}

	enc_len = RSA_size(pRsa);
	buff = (unsigned char*)malloc((total_len+enc_len)/enc_len*enc_len);
	if(NULL == buff){
		goto free_rsa;
	}

	while(len < total_len)
	{
		rc = RSA_private_encrypt(enc_len, (unsigned char*)from+len, buff + len, pRsa, RSA_NO_PADDING);
		if(rc < 0)
		{
			rc = -2;
			goto free_buff;
		}
		len += rc;
	}

	util_base64_encode(buff, len, encode);

	rc = 0;
free_buff:
	free(buff);
free_rsa:
	RSA_free(pRsa);
free_bio:
	BIO_free_all(pBp);

	return rc;
}



int test_rsa_keys(const char* public_key, const char* private_key)
{
	if(NULL == public_key || NULL == private_key)
	{
		return -1;
	}

	char password[] = "passwordpass2wordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpas3swordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword5passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordp6asswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword"; 
	int total_len = strlen(password);
	std::string encrypt;
	int rc = rsa_private_encrypt(private_key, password, total_len, encrypt);
	if(rc)
	{
		return -2;
	}

	char decrypt[10240] = {0};
	size_t dec_len = sizeof(decrypt);
	rc = rsa_public_decrypt(public_key, encrypt, decrypt, &dec_len);
	if(rc)
	{
		return -3;
	}

	rc = strncmp(password, decrypt, strlen(decrypt));
	if(rc)
	{
		return -5;
	}

	encrypt = "";
	rc  = rsa_public_encrypt(public_key, password, total_len, encrypt);
	if(rc)
	{
		return -6;
	}

	dec_len = sizeof(decrypt);
	rc = rsa_private_decrypt(private_key, encrypt, decrypt, &dec_len);
	if(rc)
	{
		return -7;
	}

	rc = strncmp(password, decrypt, strlen(decrypt));
	if(rc)
	{
		return -9;
	}

	return 0;
}

int aes_encrypt_core(const unsigned char* key, const unsigned char* s, size_t s_len, char* enc_buff, size_t* enc_len)
{
	int f_len = 0;
	int c_len = s_len + AES_BLOCK_SIZE;
	if((int)(*enc_len) < c_len){
		return -1;
	}

	unsigned int salt[] = {12345, 54321};
	int i, nrounds = 5;
	unsigned char pkey[16], iv [16];
	i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), (unsigned char*)salt, key, strlen((const char*)key), nrounds, pkey, iv);
	if(i != 16){
		return -2;
	}

	EVP_CIPHER_CTX* en_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(en_ctx);
	EVP_EncryptInit_ex(en_ctx, EVP_aes_128_cbc(), NULL, pkey, iv);

	EVP_EncryptUpdate(en_ctx, (unsigned char*)enc_buff, &c_len, s, s_len);
	EVP_EncryptFinal_ex(en_ctx, (unsigned char*)(enc_buff+c_len), &f_len);

	EVP_CIPHER_CTX_cleanup(en_ctx);
	EVP_CIPHER_CTX_free(en_ctx);
	*enc_len = c_len+f_len;
	return 0;
}

int aes_decrypt_core(const unsigned char* key, const unsigned char* encode, size_t encode_len, unsigned char* d, size_t* d_len)
{
	if(encode_len > *d_len){
		return -1;
	}

	unsigned int salt[] = {12345, 54321};
	int i, nrounds = 5;
	unsigned char pkey[16], iv [16];
	i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), (unsigned char*)salt, key, strlen((const char*)key), nrounds, pkey, iv);
	if(i != 16){
		return -2;
	}

	EVP_CIPHER_CTX* dec_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(dec_ctx);
	EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cbc(), NULL, pkey, iv);

	int f_len = 0;
	int p_len = encode_len; 

	EVP_DecryptUpdate(dec_ctx, d, &p_len, (unsigned char*)encode, encode_len);
	EVP_DecryptFinal_ex(dec_ctx, d+p_len, &f_len);
	*d_len = p_len + f_len;

	EVP_CIPHER_CTX_cleanup(dec_ctx);
	EVP_CIPHER_CTX_free(dec_ctx);
	return 0;
}

int aes_encrypt(const unsigned char* key, const unsigned char* s, size_t s_len, std::string& encode)
{
	int c_len = s_len + AES_BLOCK_SIZE;
	char* cipher_text = (char*)malloc(c_len);
	if(NULL == cipher_text){
		free(cipher_text);
		return -1;
	}

	size_t enc_len = c_len;
	int rc = aes_encrypt_core(key, s, s_len, cipher_text, &enc_len);
	if(rc){
		free(cipher_text);
		return -2;
	}
	util_base64_encode((unsigned char*)cipher_text, enc_len, encode);
	free(cipher_text);
	return 0;
}

int aes_decrypt(const unsigned char* key, const std::string& encode, unsigned char* d, size_t* d_len)
{
	size_t cipher_len = encode.size();
	char* cipher_text = (char*)malloc(cipher_len + AES_BLOCK_SIZE);
	if(NULL == cipher_text){
		return -1;
	}

	util_base64_decode(encode, cipher_text, &cipher_len);
	if(cipher_len > *d_len){
		free(cipher_text);
		return -2;
	}

	int rc = aes_decrypt_core(key, (unsigned char*)cipher_text, cipher_len, d, d_len);
	free(cipher_text);
	return rc;
}

int aes_encrypt_v(const unsigned char* key, std::vector<iovec>& iovs, char* enc_code, size_t* enc_len)
{
	char sz_buff[10240];
	if(util_get_iovec_len(iovs) > sizeof(sz_buff)){
		return -1;
	}

	if(iovs.size() == 0) return 0;

	if(iovs.size() == 1)
		return aes_encrypt_core(key, (const unsigned char*)(iovs[0].iov_base), iovs[0].iov_len, enc_code, enc_len);

	int total_len = 0;
	for(size_t i = 0; i < iovs.size(); ++i){
		memcpy(sz_buff+total_len, (const char*)iovs[i].iov_base, iovs[i].iov_len);
		total_len += iovs[i].iov_len;
	}

	return aes_encrypt_core(key, (const unsigned char*)sz_buff, total_len, enc_code, enc_len);
}

int aes_decrypt_v(const unsigned char* key, std::vector<iovec>& iovs, unsigned char* d, size_t* d_len)
{

	char sz_buff[10240];
	if(util_get_iovec_len(iovs) > sizeof(sz_buff)){
		return -1;
	}

	if(iovs.size() == 0) return 0;
	if(iovs.size() == 1)
		return aes_decrypt_core(key, (const unsigned char*)iovs[0].iov_base, iovs[0].iov_len, d, d_len);

	int total_len = 0;
	for(size_t i = 0; i < iovs.size(); ++i){
		memcpy(sz_buff+total_len, (const char*)iovs[i].iov_base, iovs[i].iov_len);
		total_len += iovs[i].iov_len;
	}

	return aes_decrypt_core(key, (const unsigned char*)sz_buff, total_len, d, d_len);
}

int test_aes(const unsigned char* key){
	char plain_text[]="dafdaaaaaaaaaaaaaaaaaaaaafewefeafjdafkafjeklheafadfefekfeaffaefeafldfeeeeeeeeeeeeeeeeeeaeereaadaerewxdfer";
	printf("plain text size:%lu\n", strlen(plain_text));
	std::string encode;
	int rc = aes_encrypt(key, (unsigned char*)plain_text, strlen(plain_text), encode);
	if(rc){
		printf("failed to encrypt\n");
		return -1;
	}

	unsigned  char decrypt[1024];
	size_t len = sizeof(decrypt);
	rc = aes_decrypt(key, encode, decrypt, &len);
	if(rc){
		printf("failed to decrypt\n");
		return -2;
	}

	printf("decrypt size:%lu\n", len);
#if 0
	if(len != strlen(plain_text)){
		printf("size not match\n");
		return -3;
	}
#endif

	rc = strncmp(plain_text, (char*)decrypt, len);
	if(rc){
		printf("content not match\n");
		printf("decrypt:%s\n", decrypt);
		printf("before :%s\n", plain_text);
		return -4;
	}

	printf("pass key:%s\n", key);
	return 0;
}
