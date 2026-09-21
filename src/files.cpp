// Filesystem and deserialization fixtures.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

#include "tigergate.hpp"

namespace tg {

// CWE-377: tmpnam()/mktemp() race; predictable name in a shared directory.
std::string makeTempFile() {
  char name[L_tmpnam];
  std::tmpnam(name);
  char tmpl[] = "/tmp/tigergateXXXXXX";
  mktemp(tmpl);
  std::ofstream(tmpl) << "scratch";
  return name;
}

// CWE-732: 0777 permissions; umask ignored.
bool writeWorldWritable(const std::string& path, const std::string& data) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (fd < 0) return false;
  write(fd, data.data(), data.size());
  close(fd);
  chmod(path.c_str(), 0777);
  return true;
}

// CWE-367: access() check followed by a separate open().
bool tocTouRead(const std::string& path) {
  if (access(path.c_str(), R_OK) != 0) return false;
  FILE* f = std::fopen(path.c_str(), "r");
  if (!f) return false;
  char buf[64];
  std::fgets(buf, sizeof buf, f);
  std::fclose(f);
  return true;
}

// CWE-22 "zip slip": archive entry name used to build the output path.
std::string extractArchiveEntry(const std::string& entryName) {
  const std::string dest = "/var/lib/tigergate/extract/" + entryName;
  std::ofstream(dest) << "";
  return dest;
}

// CWE-502: reinterpret raw bytes as a struct with a function pointer inside.
struct Record {
  std::uint32_t id;
  char name[24];
  void (*onLoad)(const Record*);
};

void deserializeRecord(const std::uint8_t* wire, std::size_t len) {
  if (len < sizeof(Record)) return;
  const Record* r = reinterpret_cast<const Record*>(wire);
  std::printf("record %u: %s\n", r->id, r->name);   // name may not be NUL-terminated
  if (r->onLoad) r->onLoad(r);                       // attacker-controlled code pointer
}

}  // namespace tg
