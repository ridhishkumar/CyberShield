#include "app.h"
#include <ctime>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <regex>
static S hex(const unsigned char *b, int n) {
  S s;
  const char *digits = "0123456789abcdef";
  for (int i = 0; i < n; ++i) {
    s += digits[b[i] >> 4];
    s += digits[b[i] & 15];
  }
  return s;
}
S randomHex(int n) {
  std::vector<unsigned char> b(n);
  if (RAND_bytes(b.data(), n) != 1)
    throw std::runtime_error("Entropy unavailable");
  return hex(b.data(), n);
}
S digest(const S &s) {
  unsigned char b[32];
  if (EVP_Digest(s.data(), s.size(), b, nullptr, EVP_sha256(), nullptr) != 1)
    throw std::runtime_error("Digest failed");
  return hex(b, 32);
}
static S derive(const S &p, const S &salt) {
  unsigned char b[32];
  if (!PKCS5_PBKDF2_HMAC(p.data(), int(p.size()),
                         (const unsigned char *)salt.data(), int(salt.size()),
                         600000, EVP_sha256(), 32, b))
    throw std::runtime_error("Hash failed");
  return salt + "$" + hex(b, 32);
}
void validName(const S &user) {
  if (!std::regex_match(user, std::regex("[A-Za-z0-9_]{3,32}")))
    throw Problem(400,
                  "Use 3–32 letters, digits or underscores for your username.");
}
S newHash(const J &j) {
  S p = field(j, "password", 128);
  if (p.size() < 12 || p != field(j, "confirm", 128))
    throw Problem(400, "Use at least 12 characters and match both passwords.");
  return derive(p, randomHex(16));
}
bool matches(const S &p, const S &hash) {
  S test = derive(p, hash.substr(0, 32));
  return test.size() == hash.size() &&
         CRYPTO_memcmp(test.data(), hash.data(), hash.size()) == 0;
}
S sessionUser(DB &db, const S &token) {
  if (token.size() != 64)
    return "";
  auto rows =
      db.query("SELECT uid FROM sessions WHERE token=? AND expires>unixepoch()",
               {digest(token)});
  return rows.empty() ? "" : std::to_string(rows[0]["uid"].get<int64_t>());
}
J auth(DB &db, const S &path, const J &j, const S &token, S &cookie) {
  if (path == "auth/register") {
    S name = field(j, "name", 80), user = field(j, "username", 32),
      email = field(j, "email", 254);
    validName(user);
    if (!std::regex_match(email, std::regex(R"([^\s@]+@[^\s@]+\.[^\s@]+)")))
      throw Problem(400, "Enter a valid email address.");
    db.query("INSERT INTO users(name,username,email,hash) VALUES(?,?,?,?)",
             {name, user, email, newHash(j)});
    db.query("INSERT INTO settings(uid,theme) VALUES(last_insert_rowid(),'dark')");
  } else if (path == "auth/login") {
    S handle = field(j, "login", 254), pass = field(j, "password", 128);
    auto rows =
        db.query("SELECT id,hash FROM users WHERE username=? OR email=?",
                 {handle, handle});
    S hash =
        rows.empty() ? S(32, '0') + "$" + S(64, '0') : rows[0]["hash"].get<S>();
    if (!matches(pass, hash) || rows.empty())
      throw Problem(401, "Invalid username/email or password.");
    S uid = std::to_string(rows[0]["id"].get<int64_t>());
    cookie = randomHex(32);
    db.query("DELETE FROM sessions WHERE expires<=unixepoch() OR token=?",
             {digest(token)});
    db.query(
        "INSERT INTO sessions(uid,token,expires) VALUES(?,?,unixepoch()+28800)",
        {uid, digest(cookie)});
    notify(db, uid, "general", "A new session signed in.");
  } else if (path == "auth/logout") {
    db.query("DELETE FROM sessions WHERE token=?", {digest(token)});
    cookie = "clear";
  } else if (path == "auth/forgot-password") {
    field(j, "email", 254);
    return {{"message", "Email recovery is unavailable on this installation. "
                        "No reset email was sent."}};
  } else
    throw Problem(404, "Unknown account action.");
  return {{"ok", true}};
}
