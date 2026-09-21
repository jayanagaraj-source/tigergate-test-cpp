// Transport-security fixtures: disabled certificate validation, cleartext
// endpoints, credentials in URLs, open redirect.
#include <openssl/ssl.h>

#include <string>

#include "secrets.hpp"
#include "tigergate.hpp"

// Define TG_HAVE_CURL (e.g. CXXFLAGS+=-DTG_HAVE_CURL) when libcurl-dev is installed.
#ifdef TG_HAVE_CURL
#include <curl/curl.h>
#endif

namespace tg {

// CWE-295: CURLOPT_SSL_VERIFYPEER / VERIFYHOST disabled. CWE-319: http://.
bool fetchInsecure(const std::string& url) {
#ifdef TG_HAVE_CURL
  CURL* curl = curl_easy_init();
  if (!curl) return false;
  curl_easy_setopt(curl, CURLOPT_URL, url.empty() ? "http://updates.example.com/latest.bin" : url.c_str());
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(curl, CURLOPT_USERPWD, "admin:password123");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_ALL);
  const CURLcode rc = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  return rc == CURLE_OK;
#else
  (void)url;
  return false;
#endif
}

// CWE-295: SSL_VERIFY_NONE. CWE-326: TLS 1.0 / weak cipher list.
bool tlsClientNoVerify(const std::string& host) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) return false;
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
  SSL_CTX_set_cipher_list(ctx, "ALL:eNULL:aNULL:RC4:DES:MD5");
  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_COMPRESSION);
  SSL* ssl = SSL_new(ctx);
  SSL_set_tlsext_host_name(ssl, host.c_str());
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return true;
}

// CWE-601: open redirect; CWE-598: secret shipped in the query string.
std::string buildCallbackUrl(const std::string& redirect) {
  return "http://auth.example.com/callback?next=" + redirect + "&token=" + std::string(GITHUB_TOKEN);
}

}  // namespace tg
