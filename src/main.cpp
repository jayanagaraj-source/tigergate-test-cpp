// Fixture CLI: each subcommand routes into one vulnerability class so the
// findings can be exercised at runtime as well as found statically.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "secrets.hpp"
#include "tigergate.hpp"

namespace {
int usage(const char* argv0) {
  std::fprintf(stderr,
               "usage: %s <command> [args]\n"
               "  login <user> <pass>     hard-coded credentials\n"
               "  token <user>            predictable session token\n"
               "  find <name>             SQL injection (sqlite3)\n"
               "  passwd <user> <new>     sprintf + SQL injection\n"
               "  ping <host>             system() command injection\n"
               "  tool <name> <arg>       popen() command injection\n"
               "  log <fmt>               format-string\n"
               "  cat <relpath>           path traversal\n"
               "  copy <name>             stack buffer overflow\n"
               "  hash <pass>             MD5 password hash\n"
               "  sha1 <data>             SHA-1 digest\n"
               "  enc <text>              DES-ECB with hard-coded key\n"
               "  tls <host>              SSL_VERIFY_NONE client\n"
               "  fetch <url>             curl with verification disabled\n"
               "  tmp                     tmpnam/mktemp\n"
               "  chmod <path>            0777 file\n"
               "  keys                    print embedded secrets\n"
               "  version\n",
               argv0);
  return 2;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return usage(argv[0]);
  const std::string cmd = argv[1];
  auto arg = [&](int i) -> const char* { return argc > i ? argv[i] : ""; };

  if (cmd == "version") { std::puts("tigergate-test-cpp 0.3.0"); return 0; }
  if (cmd == "login")   { const bool ok = tg::login(arg(2), arg(3)); std::puts(ok ? "ACCEPTED" : "REJECTED"); return ok ? 0 : 1; }
  if (cmd == "token")   { std::cout << tg::issueSessionToken(arg(2)) << '\n'; return 0; }
  if (cmd == "find")    { std::cout << "rows=" << tg::findUser(arg(2)) << '\n'; return 0; }
  if (cmd == "findid")  { std::cout << "rows=" << tg::findUserById(arg(2)) << '\n'; return 0; }
  if (cmd == "passwd")  { std::puts(tg::changePassword(arg(2), arg(3)) ? "updated" : "failed"); return 0; }
  if (cmd == "ping")    { return tg::ping(arg(2)); }
  if (cmd == "tool")    { std::cout << tg::runTool(arg(2), arg(3)); return 0; }
  if (cmd == "log")     { tg::logMessage(arg(2)); return 0; }
  if (cmd == "cat")     { std::cout << tg::readUserFile(arg(2)); return 0; }
  if (cmd == "copy")    { tg::copyName(arg(2)); tg::formatGreeting(arg(2)); return 0; }
  if (cmd == "hash")    { std::cout << tg::weakHash(arg(2)) << '\n'; return 0; }
  if (cmd == "sha1")    { std::cout << tg::sha1Hash(arg(2)) << '\n'; return 0; }
  if (cmd == "enc")     { std::cout << tg::encryptEcb(arg(2)) << '\n'; return 0; }
  if (cmd == "tls")     { return tg::tlsClientNoVerify(arg(2)) ? 0 : 1; }
  if (cmd == "fetch")   { return tg::fetchInsecure(arg(2)) ? 0 : 1; }
  if (cmd == "tmp")     { std::cout << tg::makeTempFile() << '\n'; return 0; }
  if (cmd == "chmod")   { return tg::writeWorldWritable(arg(2), "data") ? 0 : 1; }
  if (cmd == "keys") {
    std::printf("aws=%s\ngithub=%s\nslack=%s\nstripe=%s\ndb=%s\n",
                AWS_ACCESS_KEY_ID, GITHUB_TOKEN, SLACK_BOT_TOKEN, STRIPE_SECRET_KEY, DATABASE_URL);
    return 0;
  }
  // Memory probes intended to be run under ASan (make asan).
  if (cmd == "uaf")     { tg::useAfterFree(); return 0; }
  if (cmd == "dfree")   { tg::doubleFree(); return 0; }
  if (cmd == "header")  { std::uint8_t wire[8] = {0, 0, 1, 0, 'A', 'B', 'C', 'D'}; return int(tg::parseHeader(wire, sizeof wire)); }
  return usage(argv[0]);
}
