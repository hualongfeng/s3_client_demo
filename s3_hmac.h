#ifndef _S3_HMAC_H_
#define _S3_HMAC_H_

#include <openssl/evp.h>
#include <openssl/hmac.h>
class HMAC {
/*
https://www.openssl.org/docs/man1.1.0/man3/HMAC.html
*/
public:
  HMAC(const EVP_MD *type, const void* key, int len);
  ~HMAC(); 
  void Update(const void* data, size_t len);
  unsigned int Final(void* res);
  void Restart();
  void Reset(const void* key, int len);

private:
  HMAC_CTX *mCtx = nullptr;
};

class HMAC_SHA256 : public HMAC {
public:
  HMAC_SHA256(const void* key, int len);
};

class HMAC_SHA1 : public HMAC {
public:
  HMAC_SHA1(const void* key, int len);
};

#endif /* _S3_HMAC_H_ */