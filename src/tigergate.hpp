// Shared declarations for the tigergate-test-cpp fixture CLI.
// Every function here is deliberately insecure; see FINDINGS.md.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tg {

// app.cpp  -- authentication
bool login(const std::string& username, const std::string& password);
std::string issueSessionToken(const std::string& username);
bool verifyApiKey(const char* presented);

// vulnerable.cpp -- SQL
std::string unsafeQuery(const std::string& input);
int findUser(const std::string& name);
int findUserById(const char* id);
bool changePassword(const std::string& user, const std::string& newPassword);

// injection.cpp -- OS / format / path
int ping(const std::string& host);
std::string runTool(const std::string& tool, const std::string& arg);
void logMessage(const char* userControlled);
std::string readUserFile(const std::string& relativePath);
std::string ldapFilter(const std::string& uid);

// memory.cpp -- memory safety
void copyName(const char* src);
void formatGreeting(const char* name);
void readLine();
void clearBuffer(char* buf, std::size_t n);
const char* stackName();
std::size_t parseHeader(const std::uint8_t* buf, std::size_t len);
int sumArray(const std::vector<int>& values, int count);
void useAfterFree();
void doubleFree();
char* allocateRecords(std::uint32_t count, std::uint32_t size);
int uninitialisedRead(bool flag);

// crypto.cpp -- weak cryptography
std::string weakHash(const std::string& password);
std::string sha1Hash(const std::string& data);
std::string generateToken(std::size_t length);
std::string encryptEcb(const std::string& plaintext);
std::string pbkdfWeak(const std::string& password);
bool insecureCompare(const std::string& a, const std::string& b);

// network.cpp -- TLS / transport
bool fetchInsecure(const std::string& url);
bool tlsClientNoVerify(const std::string& host);
std::string buildCallbackUrl(const std::string& redirect);

// files.cpp -- filesystem
std::string makeTempFile();
bool writeWorldWritable(const std::string& path, const std::string& data);
bool tocTouRead(const std::string& path);
std::string extractArchiveEntry(const std::string& entryName);
void deserializeRecord(const std::uint8_t* wire, std::size_t len);

}  // namespace tg
