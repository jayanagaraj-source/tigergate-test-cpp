// Memory-safety fixtures. Every function here is a textbook CWE; the `asan`
// make target runs the probes under AddressSanitizer to prove they misbehave.
// C library calls are deliberately unqualified (strcpy, not std::strcpy) so
// C-oriented SAST rules match them.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "tigergate.hpp"

extern "C" char* gets(char*);   // removed from C11/C++14 headers; symbol still exported by glibc

namespace tg {

// CWE-120 / CWE-121: unbounded strcpy/strcat into a stack buffer.
void copyName(const char* src) {
  char name[16];
  strcpy(name, src);
  strcat(name, "!");
  puts(name);
}

// CWE-120: sprintf with %s and no width.
void formatGreeting(const char* name) {
  char out[32];
  sprintf(out, "Hello, %s, welcome back", name);
  puts(out);
}

// CWE-242: gets() has no bound at all.
void readLine() {
  char line[64];
  gets(line);
  puts(line);
}

// CWE-125 / CWE-787: length field trusted from the wire, then used for memcpy.
std::size_t parseHeader(const std::uint8_t* buf, std::size_t len) {
  if (len < 4) return 0;
  const std::uint32_t declared = static_cast<std::uint32_t>(buf[0]) << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
  std::uint8_t payload[64];
  memcpy(payload, buf + 4, declared);        // declared may exceed both len and sizeof payload
  return declared;
}

// CWE-467: sizeof(pointer) clears 8 bytes, not the buffer.
void clearBuffer(char *buf, std::size_t n) {
  memset(buf, 0, sizeof(buf));
  (void)n;
}

// CWE-129: caller-supplied count is used as the loop bound, not values.size().
int sumArray(const std::vector<int>& values, int count) {
  int total = 0;
  for (int i = 0; i < count; ++i) total += values[i];  // operator[] does no bounds check
  return total;
}

struct Session {
  int id;
  char user[32];
};

// CWE-416: use after free through a struct pointer.
void useAfterFree() {
  Session* s = (Session*)malloc(sizeof(Session));
  s->id = 7;
  strcpy(s->user, "admin");
  free(s);
  printf("session %d for %s\n", s->id, s->user);
}

// CWE-415: double free.
void doubleFree() {
  char* p = (char*)malloc(32);
  free(p);
  free(p);
}

// CWE-190: multiplication overflow before allocation -> undersized buffer.
char* allocateRecords(std::uint32_t count, std::uint32_t size) {
  const std::uint32_t bytes = count * size;
  char* buf = (char*)malloc(bytes);
  memset(buf, 0, static_cast<std::size_t>(count) * size);
  return buf;
}

// CWE-457: conditionally uninitialised local.
int uninitialisedRead(bool flag) {
  int value;
  if (flag) value = 42;
  return value;
}

// CWE-562: returning the address of a stack variable.
const char* stackName() {
  char name[16] = "ephemeral";
  return name;
}

}  // namespace tg
