#include "app.h"
#include <cctype>
#include <memory>
std::filesystem::path root;
DB::DB() {
  if (sqlite3_open(
          (root / "backend/database/cybershield.db").u8string().c_str(), &db) !=
      SQLITE_OK) {
    sqlite3_close(db);
    throw std::runtime_error("Database unavailable");
  }
  sqlite3_busy_timeout(db, 5000);
  script("PRAGMA foreign_keys=ON");
}
DB::~DB() { sqlite3_close(db); }
void DB::script(const char *sql) {
  if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
    throw std::runtime_error("Database operation failed");
}
J DB::query(const char *sql, const Args &args) {
  sqlite3_stmt *raw = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &raw, nullptr) != SQLITE_OK)
    throw std::runtime_error("Invalid query");
  std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(
      raw, sqlite3_finalize);
  int index = 1;
  for (auto &a : args)
    sqlite3_bind_text(raw, index++, a.data(), int(a.size()), SQLITE_TRANSIENT);
  J rows = J::array();
  int rc;
  while ((rc = sqlite3_step(raw)) == SQLITE_ROW) {
    J row = J::object();
    for (int i = 0; i < sqlite3_column_count(raw); ++i) {
      S key = sqlite3_column_name(raw, i);
      int type = sqlite3_column_type(raw, i);
      if (type == SQLITE_INTEGER)
        row[key] = sqlite3_column_int64(raw, i);
      else if (type == SQLITE_NULL)
        row[key] = nullptr;
      else
        row[key] = reinterpret_cast<const char *>(sqlite3_column_text(raw, i));
    }
    rows.push_back(row);
  }
  if (rc == SQLITE_CONSTRAINT)
    throw Problem(409, "Those account details are unavailable.");
  if (rc != SQLITE_DONE)
    throw std::runtime_error("Query failed");
  return rows;
}
void initialize(DB &db) {
  db.script(R"SQL(
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, username TEXT COLLATE NOCASE UNIQUE, email TEXT COLLATE NOCASE UNIQUE, hash TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, uid INTEGER REFERENCES users ON DELETE CASCADE, token TEXT UNIQUE, created TEXT DEFAULT CURRENT_TIMESTAMP, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(uid INTEGER PRIMARY KEY REFERENCES users ON DELETE CASCADE, theme TEXT DEFAULT 'system', security INTEGER DEFAULT 1, scans INTEGER DEFAULT 1, general INTEGER DEFAULT 1, history INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY,uid INTEGER REFERENCES users ON DELETE CASCADE, type TEXT, target TEXT, category TEXT, score INTEGER, detail TEXT, date TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS scan_owner ON scans(uid,id);
CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY,uid INTEGER REFERENCES users ON DELETE CASCADE, message TEXT,seen INTEGER DEFAULT 0,date TEXT DEFAULT CURRENT_TIMESTAMP);
)SQL");
}
S lower(S s) {
  for (char &c : s)
    c = char(std::tolower((unsigned char)c));
  return s;
}
S field(const J &j, const S &k, size_t max, bool required) {
  if (!j.contains(k) && !required)
    return "";
  if (!j.contains(k) || !j.at(k).is_string())
    throw Problem(400, "Check the " + k + " field.");
  S s = j.at(k);
  if (s.size() > max || s.find(char(0)) != S::npos ||
      (required && s.find_first_not_of(" \t\r\n") == S::npos))
    throw Problem(400, "Check the length of " + k + ".");
  return s;
}
