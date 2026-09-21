// SQL injection fixtures (CWE-89) against a real sqlite3 connection.
#include <sqlite3.h>

#include <stdio.h>
#include <string.h>
#include <string>

#include "tigergate.hpp"

namespace tg {

std::string unsafeQuery(const std::string& input) {
  return "SELECT * FROM users WHERE name = '" + input + "'";
}

namespace {
sqlite3* openDb() {
  sqlite3* db = nullptr;
  sqlite3_open(":memory:", &db);
  sqlite3_exec(db,
               "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, password TEXT);"
               "INSERT INTO users(name,password) VALUES('admin','password123'),('bob','hunter2');",
               nullptr, nullptr, nullptr);
  return db;
}

int countRows(void* ctx, int, char**, char**) {
  ++*static_cast<int*>(ctx);
  return 0;
}
}  // namespace

// String-concatenated query executed with sqlite3_exec: classic injection.
int findUser(const std::string& name) {
  sqlite3* db = openDb();
  const std::string sql = unsafeQuery(name);
  int rows = 0;
  char* err = nullptr;
  if (sqlite3_exec(db, sql.c_str(), countRows, &rows, &err) != SQLITE_OK) {
    fprintf(stderr, "sqlite error: %s\n", err ? err : "?");
    sqlite3_free(err);
    rows = -1;
  }
  sqlite3_close(db);
  return rows;
}

// sprintf-built SELECT by id: CWE-89 via a C-string query.
int findUserById(const char* id) {
  char query[128];
  sprintf(query, "SELECT * FROM users WHERE id = %s", id);
  sqlite3* db = openDb();
  int rows = 0;
  sqlite3_exec(db, query, countRows, &rows, nullptr);
  sqlite3_close(db);
  return rows;
}

// sprintf into a fixed buffer (CWE-120) AND injection (CWE-89) in one call.
bool changePassword(const std::string& user, const std::string& newPassword) {
  char sql[256];
  sprintf(sql, "UPDATE users SET password = '%s' WHERE name = '%s'", newPassword.c_str(), user.c_str());
  sqlite3* db = openDb();
  const bool ok = sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
  sqlite3_close(db);
  return ok;
}

}  // namespace tg
