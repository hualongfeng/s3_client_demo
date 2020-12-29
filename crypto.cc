#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstring>
#include <assert.h>
//g++ hmac_demo.cc -lssl  -lcrypto
#include <iostream>
#include <string>
#include "Base64.h"

extern "C" {
  const EVP_MD *EVP_md5(void);
  const EVP_MD *EVP_sha1(void);
  const EVP_MD *EVP_sha256(void);
  const EVP_MD *EVP_sha512(void);
}

/*
https://www.openssl.org/docs/man1.1.0/man3/HMAC.html
*/
HMAC::HMAC(const EVP_MD *type, const void* key, int len)
  : mCtx(HMAC_CTX_new()) {
  assert(type != nullptr && key != nullptr);
  assert(mCtx != nullptr);
  int r = HMAC_Init_ex(mCtx, key, len, type, nullptr);
  if(r != 1) {
    perror("Error: HMAC init failed");
  }
}

HMAC::~HMAC() {
  HMAC_CTX_free(mCtx);
}

void HMAC::Update(const void* data, size_t len) {
  assert(data != nullptr);
  if(len) {
    int r = HMAC_Update(mCtx, reinterpret_cast<const unsigned char*>(data), len);
    if(r != 1) {
      perror("Error: HMAC Update failed");
    }
  }
}

//unsigned int Final(unsigned char* result) {
unsigned int HMAC::Final(void* res) {
  unsigned char* result = reinterpret_cast<unsigned char*>(res);
  assert(result != nullptr);
  unsigned int len;
  int r = HMAC_Final(mCtx, result, &len);
  if(r != 1) {
      perror("Error: HMAC Final failed");
  }
  return len;
}

void HMAC::Restart() {
  int r = HMAC_Init_ex(mCtx, nullptr, 0, nullptr, nullptr);
  if(r != 1) {
    perror("Error: HMAC Restart failed");
  }
}

void HMAC::Reset(const void* key, int len) {
  assert(key != nullptr);
  int r = HMAC_Init_ex(mCtx, key, len, nullptr, nullptr);
  if(r != 1) {
    perror("Error: HMAC Reset failed");
  }
} 

HMAC_SHA256::HMAC_SHA256(const void* key, int len) 
  : HMAC(EVP_sha256(), key, len) {}

HMAC_SHA1::HMAC_SHA1(const void* key, int len) 
  : HMAC(EVP_sha1(), key, len) {}


void EvpDigest::Update(const void* data, size_t len) {
  EVP_DigestUpdate(mCtx, data, len);
}

unsigned int EvpDigest::Final(void* res) {
  unsigned int reslen;
  EVP_DigestFinal_ex(mCtx, reinterpret_cast<unsigned char*>(res), &reslen);
  return reslen;
}

int EvpDigest::Reset() {
  return EVP_MD_CTX_reset(mCtx);
}

/*

int main() {
  const char *key = "key";
  int keylen = strlen(key);
  const char *data = "The quick brown fox jumps over the lazy dog";
  int datalen = strlen(data);
  char *result = (char *)malloc(128);
  unsigned int reslen = 0;

  HMAC_SHA256 hmac_sha256(key, keylen);
  hmac_sha256.Update(data, datalen);
  reslen = hmac_sha256.Final(result);
  for(unsigned int i = 0; i < reslen; i++) {
    printf("%02hhX", result[i]);
  }
  printf("\n");

  hmac_sha256.Restart();
  hmac_sha256.Update(data, datalen);
  reslen = hmac_sha256.Final(result);
  for(unsigned int i = 0; i < reslen; i++) {
    printf("%02hhX", result[i]);
  }
  printf("\n");

  hmac_sha256.Reset(key, keylen);
  hmac_sha256.Update(data, datalen);
  reslen = hmac_sha256.Final(result);
  for(unsigned int i = 0; i < reslen; i++) {
    printf("%02hhX", result[i]);
  }
  printf("\n");

  hmac_sha256.Reset("kkk", 3);
  hmac_sha256.Reset(key, 3);
  hmac_sha256.Update(data, datalen);
  reslen = hmac_sha256.Final(result);
  for(unsigned int i = 0; i < reslen; i++) {
    printf("%02hhX", result[i]);
  }
  printf("\n");


  const char* secret_key = "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==";
  std::cout << secret_key << std::endl;
  const char* access_key = "0555b35654ad1656d804";
  std::cout << access_key << std::endl;

  const char *ls_data = "GET / HTTP/1.1\r\n"
                     "Host: 10.239.241.160:8000\r\n"
                     "Accept-Encoding: identity\r\n"
                     "Content-Length: 0\r\n"
                     "x-amz-date: Wed, 23 Dec 2020 08:38:29 +0000\r\n";

//https://docs.aws.amazon.com/zh_cn/AmazonS3/latest/dev/RESTAuthentication.html
ls_data = "GET\n"
          "\n"
          "\n"
          "\n"
          "x-amz-date:Wed, 23 Dec 2020 08:38:29 +0000\n"
          "/";

  std::cout << "string_to_sign: " << std::endl << ls_data << std::endl;
  int ls_data_len = strlen(ls_data);
  std::cout << "string_to_sign len: " << ls_data_len << std::endl;
  HMAC_SHA1 hmac_sha1(secret_key, strlen(secret_key));
  hmac_sha1.Update(ls_data, ls_data_len);
  reslen = hmac_sha1.Final(result);
  std::string ret = macaron::Base64::Encode(std::string(result, reslen));
  std::cout << "result: " << ret.compare("O6pBjK4crj/S5lXtEpsdRz6tp2I=") << std::endl;
  std::cout << ret << std::endl;

  return 0;
}

*/