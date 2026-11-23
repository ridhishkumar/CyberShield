#include "integrations.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <curl/curl.h>
#include <memory>
#include <mutex>
static S env(const char *name) {
  const char *p = std::getenv(name);
  return p ? p : "";
}
static size_t collect(char *bytes, size_t size, size_t n, void *dest) {
  auto &s = *static_cast<S *>(dest);
  if (size * n > 2 * 1024 * 1024 - s.size())
    return 0;
  s.append(bytes, size * n);
  return size * n;
}
static S fetch(const S &url, const Args &headers = {}, const S &body = "",
               long *httpStatus = nullptr, CURLcode *curlStatus = nullptr) {
  static const auto init = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (init != CURLE_OK)
    throw std::runtime_error("Network unavailable");
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> h(curl_easy_init(),
                                                        curl_easy_cleanup);
  if (!h)
    throw std::runtime_error("Network unavailable");
  curl_slist *list = nullptr;
  for (const auto &s : headers)
    list = curl_slist_append(list, s.c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> hold(
      list, curl_slist_free_all);
  S result;
  curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
  curl_easy_setopt(h.get(), CURLOPT_HTTPHEADER, list);
  curl_easy_setopt(h.get(), CURLOPT_USERAGENT,
                   "CyberShield educational client/1");
  curl_easy_setopt(h.get(), CURLOPT_TIMEOUT, 8L);
  curl_easy_setopt(h.get(), CURLOPT_NOSIGNAL, 1L);
#ifdef _WIN32
  auto ca = root / "windows-x64/ca-bundle.crt";
  S caPath = ca.u8string();
  if (std::filesystem::exists(ca))
    curl_easy_setopt(h.get(), CURLOPT_CAINFO, caPath.c_str());
#endif
  curl_easy_setopt(h.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(h.get(), CURLOPT_WRITEFUNCTION, collect);
  curl_easy_setopt(h.get(), CURLOPT_WRITEDATA, &result);
  if (!body.empty())
    curl_easy_setopt(h.get(), CURLOPT_POSTFIELDS, body.c_str());
  const auto status = curl_easy_perform(h.get());
  if (httpStatus)
    curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, httpStatus);
  if (curlStatus)
    *curlStatus = status;
  if (status != CURLE_OK)
    throw std::runtime_error("Provider unavailable");
  return result;
}
J newsFeed() {
  static std::mutex lock;
  static S cache;
  static time_t updated = 0;
  std::lock_guard<std::mutex> guard(lock);
  if (time(nullptr) - updated > 1800) {
    try {
      auto value = fetch("https://feeds.feedburner.com/TheHackersNews");
      if (value.find("<rss") != S::npos) {
        cache = value;
        updated = time(nullptr);
      }
    } catch (...) {
    }
  }
  return {{"xml", cache}, {"retrieved", updated}};
}
void reputation(J &r) {
  S key = env("TRUSTPILOT_API_KEY"), host = r.at("hostname");
  r["reputation"] = "Insufficient independent reputation information.";
  if (key.empty() || host.find(':') != S::npos)
    return;
  try {
    auto unit = J::parse(
        fetch("https://api.trustpilot.com/v1/business-units/find?name=" + host,
              {"apikey: " + key}));
    S id = unit.at("id");
    if (id.empty() || id.find_first_not_of("0123456789abcdefABCDEF") != S::npos)
      return;
    auto reviews =
        J::parse(fetch("https://api.trustpilot.com/v1/business-units/" + id +
                           "/reviews?perPage=6",
                       {"apikey: " + key}));
    auto list = reviews.at("reviews");
    if (list.empty())
      return;
    int pos = 0, neg = 0;
    auto &notes = r["notes"];
    notes.push_back("Independent review sample from Trustpilot.");
    notes.push_back("Source: https://www.trustpilot.com/review/" + host);
    for (auto &review : list) {
      int stars = review.at("stars");
      if (stars >= 4)
        ++pos;
      if (stars <= 2)
        ++neg;
      S title = review.value("title", S());
      notes.push_back(std::to_string(stars) + "/5 · " +
                      review.value("createdAt", S()) + " · " + title);
    }
    r["reputation"] = "Independent review sample available.";
    notes.push_back(pos && !neg   ? "Sample reputation: positive"
                    : neg && !pos ? "Sample reputation: poor"
                                  : "Sample reputation: mixed");
  } catch (...) { /* Existing insufficient-information result covers unavailable
                     providers. */
  }
}
J assistantReply(const J &input) {
  S msg = field(input, "message", 500), key = env("OPENAI_API_KEY"),
    model = env("CYBERSHIELD_AI_MODEL");
  if (input.value("useAI", false) && !key.empty() && !model.empty()) {
    try {
      J payload = {
          {"model", model},
          {"messages",
           J::array(
               {{{"role", "system"},
                 {"content",
                  "Give brief beginner-friendly defensive cybersecurity "
                  "guidance. You cannot scan, verify identities or operate "
                  "accounts. Redirect offensive requests to prevention."}},
                {{"role", "user"}, {"content", msg}}})}};
      auto data = J::parse(fetch(
          "https://api.openai.com/v1/chat/completions",
          {"Content-Type: application/json", "Authorization: Bearer " + key},
          payload.dump()));
      return {{"mode", "AI response"},
              {"answer", data.at("choices").at(0).at("message").at("content")}};
    } catch (...) {
    }
  }
  S text = lower(msg);
  std::vector<std::pair<Args, S>> answers = {
      {{"score", "risk", "dashboard"},
       "The dashboard averages retained numeric risk scores and subtracts the "
       "average from 100. Open a report to see exactly which indicators "
       "contributed."},
      {{"phish", "email", "sender"},
       "Phishing messages impersonate a trusted sender. Check unexpected "
       "requests through a known contact channel. The Email checker explains "
       "phrases and link indicators."},
      {{"malware", "device", "file", "virus"},
       "Use Device scanner for a selected file or consent to a local "
       "fixed-drive scan. Both require ClamAV. A completed check covers the "
       "files and signatures the engine could read."},
      {{"url", "website", "link"},
       "Paste a complete HTTP or HTTPS link into Website checker. Review the "
       "hostname, findings and reputation evidence before deciding whether to "
       "visit."},
      {{"report", "history", "pdf"},
       "Open Scan history, filter the list and select View report. Download "
       "PDF saves a copy of that report."},
      {{"password", "account", "session"},
       "Use a unique passphrase. In My profile you can change your password. "
       "Settings shows your active sessions."},
      {{"alert", "notification"},
       "Open the bell to see scan and account events. Settings controls which "
       "events create notifications."}};
  S answer =
      "I can explain phishing, URL checks, passwords, device scans, dashboard "
      "scores and PDF reports. Which would you like to explore?";
  for (auto &item : answers) {
    bool hit = false;
    for (auto &word : item.first)
      if (text.find(word) != S::npos)
        hit = true;
    if (hit) {
      answer = item.second;
      break;
    }
  }
  return {{"mode", "Local FAQ"}, {"answer", answer}};
}
