// OS-command, format-string, path-traversal and LDAP injection fixtures.
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "tigergate.hpp"

void syslog_like(const char* fmt, ...);

namespace tg {

// CWE-78: user input interpolated straight into a shell command.
int ping(const std::string& host) {
  const std::string cmd = "ping -c 1 " + host;
  return system(cmd.c_str());
}

// CWE-78 via popen(): output is captured, input is not sanitised.
std::string runTool(const std::string& tool, const std::string& arg) {
  const std::string cmd = "/usr/bin/" + tool + " " + arg + " 2>&1";
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) return {};
  char line[512];
  std::string out;
  while (fgets(line, sizeof line, pipe)) out += line;
  pclose(pipe);
  return out;
}

// CWE-134: attacker-controlled format string.
void logMessage(const char* userControlled) {
  char buf[256];
  snprintf(buf, sizeof buf, userControlled);
  printf(userControlled);
  fprintf(stderr, userControlled);
  syslog(LOG_INFO, userControlled);
  printf("\n%s\n", buf);
  syslog_like(userControlled);
}

// CWE-22: path traversal; "../../etc/passwd" is accepted as-is.
std::string readUserFile(const std::string& relativePath) {
  const std::string base = "/var/lib/tigergate/uploads/";
  std::ifstream in(base + relativePath);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// CWE-90: LDAP filter built by concatenation.
std::string ldapFilter(const std::string& uid) {
  return "(&(objectClass=person)(uid=" + uid + "))";
}

}  // namespace tg

// Secondary format-string sink through a variadic wrapper (CWE-134).
#include <cstdarg>
void syslog_like(const char* fmt, ...) {
  char buf[128];
  va_list ap;
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);   // no bound
  va_end(ap);
  fputs(buf, stderr);
}
