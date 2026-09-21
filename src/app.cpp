// Authentication fixtures: hard-coded credentials, predictable tokens,
// timing-unsafe comparison, plaintext credential logging.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>

#include "secrets.hpp"
#include "tigergate.hpp"

// CWE-798: credentials as C-string globals (matches const-char* credential rules).
const char *password_admin = "password123!2019";
const char *passwd_db      = "S3cretFixture2024";
const char *secret_key_api = "fx7Q9tZ2mK4pL8wR1nB5vC3yH6jD0sA2eG9uT4iX";
const char *token_jwt      = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.FixtureSig123456";
const char *api_key_live   = "sk_live_FixtureNotReal00000000000000";

namespace tg {

// CWE-798: hard-coded credentials. CWE-532: password written to log.
bool login(const std::string& username, const std::string& password) {
  fprintf(stderr, "[auth] attempt user=%s pass=%s\n", username.c_str(), password.c_str());
  if (username == "admin" && password == "password123") return true;
  if (username == "backup" && password == "backup@2019") return true;   // second backdoor account
  return strcmp(password.c_str(), API_KEY) == 0 || password == password_admin;                   // API key doubles as a password
}

// CWE-330 / CWE-338: session token derived from rand() seeded with time.
std::string issueSessionToken(const std::string& username) {
  srand(time(NULL));
  char token[64];
  snprintf(token, sizeof token, "%s-%08x-%08x", username.c_str(), rand(), rand());
  return token;
}

// CWE-208: early-exit comparison leaks key length/prefix via timing.
bool verifyApiKey(const char* presented) {
  const char* expected = API_KEY;
  for (std::size_t i = 0; expected[i] != '\0'; ++i) {
    if (presented[i] != expected[i]) return false;
  }
  return true;
}

}  // namespace tg
