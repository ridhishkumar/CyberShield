#include "app.h"
void validName(const S &);
S newHash(const J &);
bool matches(const S &, const S &);
J account(DB &db, const S &uid, const S &path, const S &method, const J &j,
          const S &token) {
  if ((path == "profile" || path == "auth/me") && method == "GET")
    return db
        .query("SELECT id,name,username,email,created,'Active' AS status FROM "
               "users WHERE id=?",
               {uid})
        .at(0);
  if (path == "profile" && method == "PUT") {
    S user = field(j, "username", 32);
    validName(user);
    db.query("UPDATE users SET name=?,username=? WHERE id=?",
             {field(j, "name", 80), user, uid});
  } else if ((path == "profile/change-password" && method == "POST") ||
             (path == "profile" && method == "DELETE")) {
    if (!matches(
            field(j, "current", 128),
            db.query("SELECT hash FROM users WHERE id=?", {uid})[0]["hash"]))
      throw Problem(403, "Check your current password.");
    if (method == "DELETE")
      db.query("DELETE FROM users WHERE id=?", {uid});
    else {
      db.query("UPDATE users SET hash=? WHERE id=?", {newHash(j), uid});
      db.query("DELETE FROM sessions WHERE uid=?", {uid});
    }
  } else if (path == "settings" && method == "GET")
    return db
        .query("SELECT theme,security,scans,general,history FROM settings "
               "WHERE uid=?",
               {uid})
        .at(0);
  else if (path == "settings" && method == "PUT") {
    S t = field(j, "theme", 8);
    if (t != "system" && t != "dark" && t != "light")
      throw Problem(400, "Unknown theme.");
    Args args = {t};
    for (auto k : {"security", "scans", "general", "history"}) {
      if (!j.contains(k) || !j.at(k).is_boolean())
        throw Problem(400, "Choose each preference.");
      args.push_back(j[k].get<bool>() ? "1" : "0");
    }
    args.push_back(uid);
    db.query("UPDATE settings SET "
             "theme=?,security=?,scans=?,general=?,history=? WHERE uid=?",
             args);
  } else if (path == "sessions" && method == "GET")
    return db.query(
        "SELECT id,created,datetime(expires,'unixepoch') AS expires,token=? AS "
        "current FROM sessions WHERE uid=? AND expires>unixepoch()",
        {digest(token), uid});
  else if (path == "sessions" && method == "DELETE")
    db.query("DELETE FROM sessions WHERE uid=? AND token<>?",
             {uid, digest(token)});
  else
    throw Problem(404, "Unknown endpoint.");
  return {{"ok", true}};
}
