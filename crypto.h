#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/evp.h>
#include <openssl/hmac.h>
//#include <openssl/sha.h>

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

//EVP_MAX_MD_SIZE

//https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit_ex.html
class EvpDigest {
public:
  EvpDigest(const EVP_MD *type): mCtx(EVP_MD_CTX_new()) {
    EVP_DigestInit_ex(mCtx, type, nullptr);
  }

  EvpDigest(const char* name): mCtx(EVP_MD_CTX_new()) {
    auto md = EVP_get_digestbyname(name);
    EVP_DigestInit_ex(mCtx, md, nullptr);
  }

  ~EvpDigest() {
    EVP_MD_CTX_free(mCtx);
  }

  void Update(const void* data, size_t len);
  unsigned int Final(void* res);
  int Reset();
private:
  EVP_MD_CTX *mCtx;
};

class MD5 : public EvpDigest {
public:
  MD5() : EvpDigest("md5"){}
};

class SHA1 : public EvpDigest {
public:
  SHA1() : EvpDigest(EVP_sha1()){}
};

class SHA256 : public EvpDigest {
public:
  SHA256() : EvpDigest(EVP_sha256()){}
};

#endif /* _S3_HMAC_H_ */
