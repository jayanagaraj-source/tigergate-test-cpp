// Weak-cryptography fixtures built on the real OpenSSL API.
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iomanip>
#include <sstream>
#include <string>

#include "secrets.hpp"
#include "tigergate.hpp"

namespace tg {
namespace {
std::string hex(const unsigned char* d, std::size_t n) {
  std::ostringstream o;
  for (std::size_t i = 0; i < n; ++i) o << std::hex << std::setw(2) << std::setfill('0') << int(d[i]);
  return o.str();
}
}  // namespace

// CWE-328: MD5 for password storage, unsalted.
std::string weakHash(const std::string& password) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const unsigned char*>(password.data()), password.size(), digest);
  return hex(digest, sizeof digest);
}

// CWE-328: SHA-1 for integrity.
std::string sha1Hash(const std::string& data) {
  unsigned char digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
  return hex(digest, sizeof digest);
}

// CWE-338: rand() is not a CSPRNG; seed is the wall clock.
std::string generateToken(std::size_t length) {
  static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  srand(time(NULL));
  std::string t;
  for (std::size_t i = 0; i < length; ++i) t += alphabet[rand() % (sizeof alphabet - 1)];
  return t;
}

// CWE-327 (DES) + CWE-329 (ECB, no IV) + CWE-321 (hard-coded key).
std::string encryptEcb(const std::string& plaintext) {
  DES_cblock key;
  memcpy(key, ENCRYPTION_KEY, sizeof key);
  DES_key_schedule ks;
  DES_set_key_unchecked(&key, &ks);

  std::string padded = plaintext;
  while (padded.size() % 8) padded += '\0';
  std::string out(padded.size(), '\0');
  for (std::size_t i = 0; i < padded.size(); i += 8) {
    DES_ecb_encrypt(reinterpret_cast<const_DES_cblock*>(&padded[i]),
                    reinterpret_cast<DES_cblock*>(&out[i]), &ks, DES_ENCRYPT);
  }
  return hex(reinterpret_cast<const unsigned char*>(out.data()), out.size());
}

// CWE-916: PBKDF2 with 1 iteration and a static salt.
std::string pbkdfWeak(const std::string& password) {
  static const unsigned char salt[] = "static-salt";
  unsigned char key[16];
  PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), int(password.size()), salt, sizeof salt - 1, 1, sizeof key, key);
  return hex(key, sizeof key);
}

// CWE-208: std::string operator== short-circuits on first mismatch.
bool insecureCompare(const std::string& a, const std::string& b) {
  return a == b;
}

}  // namespace tg
