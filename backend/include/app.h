#pragma once
#include "json.hpp"
#include "sqlite3.h"
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
using J = nlohmann::json;
using S = std::string;
using Args = std::vector<S>;
struct Problem : std::runtime_error {
  int status;
  Problem(int status, const S &message)
      : std::runtime_error(message), status(status) {}
};
class DB {
  sqlite3 *db = nullptr;

public:
  DB();
  ~DB();
  DB(const DB &) = delete;
  J query(const char *sql, const Args &args = {});
  void script(const char *sql);
};
extern std::filesystem::path root;
S field(const J &, const S &, size_t max, bool required = true);
S lower(S);
S randomHex(int);
S digest(const S &);
S sessionUser(DB &, const S &token);
J auth(DB &, const S &, const J &, const S &, S &cookie);
J account(DB &, const S &, const S &, const S &, const J &, const S &);
J analyze(const S &, const J &);
J workspace(DB &, const S &, const S &, const S &, const J &);
void record(DB &, const S &, J &);
void notify(DB &, const S &, const S &, const S &);
void initialize(DB &);
