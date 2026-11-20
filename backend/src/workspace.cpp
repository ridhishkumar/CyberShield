#include "app.h"
#include "scanner.h"
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <thread>
bool workerInstalled();
void runLocalWorker(const std::function<void(scanner::Progress)> &);
static std::mutex jobMutex;
static S jobOwner;
static J job = {{"state", "idle"}};
static bool deviceEnabled() {
#ifdef _WIN32
  const char *setting = std::getenv("CYBERSHIELD_LOCAL_SCANNER");
  return workerInstalled() && (!setting || S(setting) != "0");
#else
  return false;
#endif
}
void notify(DB &db, const S &uid, const S &preference, const S &message) {
  auto opts = db.query(
      "SELECT scans,security,general FROM settings WHERE uid=?", {uid});
  if (!opts.empty() && opts[0][preference] == 1)
    db.query("INSERT INTO notices(uid,message) VALUES(?,?)", {uid, message});
}
void record(DB &db, const S &uid, J &report) {
  report["date"] = db.query("SELECT CURRENT_TIMESTAMP AS value")[0]["value"];
  if (uid.empty())
    return;
  if (db.query("SELECT history FROM settings WHERE uid=?", {uid})
          .at(0)["history"] == 1) {
    db.query("INSERT INTO scans(uid,type,target,category,score,detail) "
             "VALUES(?,?,?,?,NULLIF(?,'null'),?)",
             {uid, report["type"], report["target"], report["category"],
              report["score"].dump(), report.dump()});
  }
  notify(db, uid, "scans", report["type"].get<S>() + " check completed.");
  if (report["category"] == "High risk")
    notify(db, uid, "security", "A check returned a high-risk result.");
}
static J engineReport(S type, S target, int64_t checked, int64_t threats,
                      int64_t skipped) {
  S category = threats               ? "High risk"
               : !checked || skipped ? "Insufficient information"
                                     : "Lower risk";
  return {
      {"type", type},
      {"target", target},
      {"category", category},
      {"score", nullptr},
      {"detections", threats},
      {"source", "Local ClamAV daemon"},
      {"findings", J::array()},
      {"notes",
       {"Files checked: " + std::to_string(checked),
        "Detections: " + std::to_string(threats),
        "Skipped or failed: " + std::to_string(skipped)}},
      {"advice",
       threats
           ? "Review the findings in your antivirus tool before opening files."
           : "Keep signatures current. Coverage depends on engine limits and "
             "file access."}};
}
J workspace(DB &db, const S &uid, const S &path, const S &method, const J &j) {
  if (path == "device" && method == "GET") {
    const bool engine = scanner::available();
    std::lock_guard<std::mutex> lock(jobMutex);
    J r = jobOwner == uid ? job : J{{"state", "idle"}};
    r["fileReady"] = engine;
    r["helperReady"] = deviceEnabled();
    r["enabled"] = engine && deviceEnabled();
    r["busy"] = job["state"] == "running";
    return r;
  }
  if (path == "device" && method == "POST") {
    if (!deviceEnabled() || !j.value("consent", false))
      throw Problem(400,
                    "Enable the Windows local scanner and confirm the scan.");
    if (!scanner::available()) throw Problem(503, "Start the local ClamAV engine and check again.");
    std::lock_guard<std::mutex> lock(jobMutex);
    if (job["state"] == "running")
      throw Problem(409, "A device scan is already running.");
    jobOwner = uid;
    job = {
        {"state", "running"}, {"checked", 0}, {"detected", 0}, {"errors", 0}};
    std::thread([uid] {
      try {
        scanner::Progress last;
        runLocalWorker([&](auto p) {
          last = p;
          std::lock_guard<std::mutex> lock(jobMutex);
          job["checked"] = p.checked;
          job["detected"] = p.detected;
          job["errors"] = p.errors;
        });
        J result = engineReport("Device", "Fixed Windows drives", last.checked,
                                last.detected, last.errors);
        DB db;
        db.script("BEGIN IMMEDIATE");
        record(db, uid, result);
        db.script("COMMIT");
        std::lock_guard<std::mutex> lock(jobMutex);
        job = {{"state", "done"}, {"report", result}};
      } catch (...) {
        std::lock_guard<std::mutex> lock(jobMutex);
        job = {{"state", "failed"},
               {"message", "Could not complete scan. Check local ClamAV "
                           "availability and access."}};
      }
    }).detach();
    J accepted = job;
    accepted["enabled"] = true;
    accepted["fileReady"] = true;
    accepted["helperReady"] = true;
    accepted["busy"] = true;
    return accepted;
  }
  if ((path == "history" || path == "history/search") && method == "GET")
    return db.query(
        "SELECT id,type,target,date,category,score FROM scans WHERE uid=? AND "
        "(target LIKE ? OR type LIKE ?) ORDER BY id DESC LIMIT 500",
        {uid, "%" + j.value("q", S()) + "%", "%" + j.value("q", S()) + "%"});
  if (path == "report" && method == "GET") {
    auto r = db.query("SELECT detail FROM scans WHERE uid=? AND id=?",
                      {uid, j.value("id", S())});
    if (r.empty())
      throw Problem(404, "Report unavailable.");
    return J::parse(r[0]["detail"].get<S>());
  }
  if (path == "history" && method == "DELETE") {
    db.query("DELETE FROM scans WHERE uid=?", {uid});
    return {{"ok", true}};
  }
  if (path == "notifications" && method == "GET")
    return db.query("SELECT id,message,date,seen FROM notices WHERE uid=? "
                    "ORDER BY id DESC LIMIT 50",
                    {uid});
  if (path == "notifications" && method == "PUT") {
    db.query("UPDATE notices SET seen=1 WHERE uid=?", {uid});
    return {{"ok", true}};
  }
  if (path == "dashboard" && method == "GET")
    return {
        {"counts",
         db.query(
             "SELECT type,count(*) AS n FROM scans WHERE uid=? GROUP BY type",
             {uid})},
        {"summary", db.query("SELECT count(*) AS total, round(100-avg(CASE "
                             "WHEN typeof(score)='integer' THEN score END)) AS "
                             "health, sum(category='High risk') AS high, "
                             "coalesce(sum(json_extract(detail,'$.detections'))"
                             ",0) AS detections FROM scans WHERE uid=?",
                             {uid})[0]},
        {"trend",
         db.query(
             "SELECT substr(date,1,10) AS day,count(*) AS n,round(100-avg(CASE "
             "WHEN typeof(score)='integer' THEN score END)) AS health FROM "
             "scans WHERE uid=? GROUP BY day ORDER BY day DESC LIMIT 7",
             {uid})},
        {"recent", db.query("SELECT id,type,target,date,category,score FROM "
                            "scans WHERE uid=? ORDER BY id DESC LIMIT 5",
                            {uid})}};
  throw Problem(404, "Unknown endpoint.");
}
