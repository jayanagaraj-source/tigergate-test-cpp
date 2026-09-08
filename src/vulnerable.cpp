#include <string>
std::string unsafeQuery(const std::string& input) { return "SELECT * FROM users WHERE name = '" + input + "'"; }
