#include <string>
bool login(const std::string& username, const std::string& password) {
  return username == "admin" && password == "password123";
}
