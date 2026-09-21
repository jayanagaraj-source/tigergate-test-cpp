// Minimal assert-based tests (no external framework so the fixture builds anywhere).
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

#include "tigergate.hpp"

int main() {
  assert(tg::login("admin", "password123"));
  assert(!tg::login("admin", "wrong"));
  assert(!tg::login("Admin", "password123"));

  assert(tg::unsafeQuery("bob") == "SELECT * FROM users WHERE name = 'bob'");
  assert(tg::findUser("bob") == 1);
  assert(tg::findUser("nobody") == 0);
  assert(tg::findUserById("1 OR 1=1") == 2);
  assert(tg::findUser("' OR '1'='1") == 2);   // injection returns every row

  assert(tg::weakHash("hunter2") == "2ab96390c7dbe3439de74d0c9b0b1767");
  assert(tg::sha1Hash("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d");
  assert(tg::ldapFilter("x)(uid=*") == "(&(objectClass=person)(uid=x)(uid=*))");
  assert(tg::buildCallbackUrl("//evil.example").rfind("http://auth.example.com/callback?next=//evil.example", 0) == 0);

  std::puts("all tests passed");
  return 0;
}
