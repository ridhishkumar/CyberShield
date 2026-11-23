#include <thread>

#include "app.h"
#include "crow.h"
#include "integrations.h"
#include "website_inspector.h"
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <regex>
namespace fs = std::filesystem;
J analyzeFile(const S &, const S &);
J softwareSources();
static S tokenOf(const crow::request &req) {
  std::istringstream in(req.get_header_value("Cookie"));
  S item;
  while (std::getline(in, item, ';')) {
    item.erase(0, item.find_first_not_of(' '));
    if (item.rfind("cs_session=", 0) == 0)
      return item.substr(11);
  }
  return "";
}
static crow::response reply(int code, const J &j) {
  crow::response r(code, j.dump());
  r.set_header("Content-Type", "application/json; charset=utf-8");
  r.set_header("Cache-Control", "no-store");
  r.set_header("X-Content-Type-Options", "nosniff");
  return r;
}
static void limit(const S &k, int max) {
  static std::mutex m;
  static std::map<S, std::pair<time_t, int>> counts;
  std::lock_guard<std::mutex> lock(m);
  auto &entry = counts[k];
  auto now = std::time(nullptr);
  if (now - entry.first >= 60)
    entry = {now, 0};
  if (++entry.second > max)
    throw Problem(429, "Please try again in one minute.");
}
static bool local(const crow::request &req) {
  auto host = lower(req.get_header_value("Host"));
  return host == "localhost:8080" || host == "127.0.0.1:8080";
}
static crow::response api(const crow::request &req, S path) {
  try {
    if (!local(req))
      throw Problem(403, "Use the local CyberShield address.");
    S method = crow::method_name(req.method), token = tokenOf(req), cookie;
    bool write = method != "GET";
    bool file = path == "check-file";
    if (req.body.size() > (file ? 8u * 1024 * 1024 : 65536u))
      throw Problem(413, "Input exceeds the size limit.");
    if (write && req.get_header_value("X-CyberShield") != "1")
      throw Problem(403, "Use a same-origin request.");
    limit(req.remote_ip_address +
              (path == "auth/login" || path == "auth/register" ? "/account"
                                                               : "/api"),
          path == "auth/login" || path == "auth/register" ? 20 : 600);
    J data = J::object();
    if (!file && !req.body.empty()) {
      data = J::parse(req.body);
      if (!data.is_object())
        throw Problem(400, "Expected an object.");
    }
    for (auto key : {"q", "id"})
      if (auto value = req.url_params.get(key))
        data[key] = S(value);
    DB db;
    S uid = sessionUser(db, token);
    const bool accountEntry =
        method == "POST" &&
        (path == "auth/login" || path == "auth/register" ||
         path == "auth/forgot-password" || path == "auth/logout");
    if (uid.empty() && !accountEntry)
      throw Problem(401, "Please sign in.");
    if (path == "software-sources" && method == "GET")
      return reply(200, softwareSources());
    J result;
    if (path == "assistant" && method == "POST" && !uid.empty()) {
      limit("assistant:" + req.remote_ip_address, 12);
      return reply(200, assistantReply(data));
    }
    if (path == "news" && method == "GET" && !uid.empty())
      return reply(200, newsFeed());
    bool detector =
        method == "POST" && (path == "check-url" || path == "check-email" ||
                             path == "check-software" || path == "check-sms");
    if (detector) {
      if (path == "check-url") {
        result = website_inspector::inspectWebsite(data);
      } else {
        result = analyze(path == "check-email" ? "Email"
                         : path == "check-sms" ? "SMS"
                                                : "Software",
                         data);
        if (result.contains("hostname")) {
          if (data.value("dnsLookup", false))
            checkDns(result);
          reputation(result);
        }
      }
    }
    if (file && method == "POST") {
      if (req.body.empty())
        throw Problem(400, "Choose a nonempty file.");
      result = analyzeFile(req.body,
                           lower(req.get_header_value("X-File-Extension")));
    }
    if (write) {
      db.script("BEGIN IMMEDIATE");
      uid = sessionUser(db, token);
      if (uid.empty() && !accountEntry)
        throw Problem(401, "Please sign in.");
    }
    if (path.rfind("auth/", 0) == 0 && path != "auth/me" && method == "POST")
      result = auth(db, path, data, token, cookie);
    else if (detector || (file && method == "POST"))
      record(db, uid, result);
    else if (path == "tips" && method == "GET")
      result = {
          "Open a bookmarked sign-in page when an email asks you to act.",
          "Use a different password for each account.",
          "Confirm unexpected payment requests by calling a known number."};
    else if (uid.empty())
      throw Problem(401, "Please sign in.");
    else if (path == "settings" || path == "sessions" || path == "auth/me" ||
             path.rfind("profile", 0) == 0)
      result = account(db, uid, path, method, data, token);
    else
      result = workspace(db, uid, path, method, data);
    if (write)
      db.script("COMMIT");
    auto r = reply(200, result);
    if (!cookie.empty())
      r.set_header("Set-Cookie",
                   "cs_session=" + cookie +
                       "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                       (cookie == "clear" ? "0" : "28800"));
    return r;
  } catch (const Problem &e) {
    return reply(e.status, {{"error", e.what()}});
  } catch (const J::exception &) {
    return reply(400, {{"error", "Invalid request data."}});
  } catch (const std::exception &) {
    return reply(500, {{"error", "The operation could not be completed."}});
  }
}
static crow::response page(const crow::request &req, S path) {
  if (!local(req))
    return crow::response(403);
  if (path.empty() || path == "index.html") {
    crow::response r(302);
    r.set_header("Location", "/login.html");
    return r;
  }
  if (path.find("..") != S::npos ||
      !std::regex_match(path, std::regex("[A-Za-z0-9_./-]+")))
    return crow::response(404);
  if (path != fs::path(path).lexically_normal().generic_string() ||
      path.find('/') == 0)
    return crow::response(404);
  if (fs::path(path).extension() == ".html" && path != "login.html" &&
      path != "signup.html" && path != "forgot-password.html") {
    DB db;
    if (sessionUser(db, tokenOf(req)).empty()) {
      crow::response r(302);
      r.set_header("Location", "/login.html");
      return r;
    }
  }
  auto f = root / "frontend" / path;
  std::ifstream in(f, std::ios::binary);
  if (!in || !fs::is_regular_file(f))
    return crow::response(404);
  std::ostringstream buf;
  buf << in.rdbuf();
  crow::response r(buf.str());
  auto ext = f.extension().string();
  std::map<S, S> types = {{".html", "text/html; charset=utf-8"},
                          {".css", "text/css"},
                          {".js", "text/javascript"},
                          {".svg", "image/svg+xml"},
                          {".json", "application/json"},
                          {".woff2", "font/woff2"},
                          {".ttf", "font/ttf"}};
  r.set_header("Content-Type",
               types.count(ext) ? types[ext] : "application/octet-stream");
  r.set_header("X-Content-Type-Options", "nosniff");
  r.set_header("Cache-Control", "no-store");
  r.set_header("Content-Security-Policy",
               "default-src 'self'; script-src 'self'; style-src 'self' "
               "'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; "
               "object-src 'none'");
  return r;
}
int main(int argc, char **argv) {
  try {
    root = fs::absolute(argc > 1 ? fs::path(argv[1]) : fs::current_path());
    if (!fs::exists(root / "frontend/login.html"))
      throw std::runtime_error("Start from the extracted CyberShield folder.");
    fs::create_directories(root / "backend/database");
    DB db;
    initialize(db);
    std::cout << "Account database: "
              << (root / "backend/database/cybershield.db")
                     .lexically_normal()
                     .u8string()
              << std::endl;
    crow::SimpleApp app;
    CROW_ROUTE(app, "/api/<path>")
        .methods(crow::HTTPMethod::GET, crow::HTTPMethod::POST,
                 crow::HTTPMethod::PUT, crow::HTTPMethod::Delete)(api);
    CROW_ROUTE(app,
               "/")([](const crow::request &req) { return page(req, ""); });
    CROW_ROUTE(app, "/<path>")(page);
    app.bindaddr("127.0.0.1").port(8080).concurrency(4).run();
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
}
