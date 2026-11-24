#include "website_inspector.h"
#include "website_domain_denylist_config.h"
#include "website_tld_config.h"

#include <asio.hpp>
#include <curl/curl.h>
#include <openssl/x509_vfy.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>

namespace website_inspector {
S categoryForScore(int score) {
  score = std::max(0, std::min(100, score));
  if (score >= 61)
    return "Highly Risky";
  if (score >= 36)
    return "Be Cautious";
  return "Safe";
}
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t MaxBodyBytes = 1024 * 1024;
constexpr size_t MaxHeaderBytes = 32 * 1024;
constexpr int MaxRedirects = 4;

CURLcode initializeCurl() {
  static const CURLcode result = curl_global_init(CURL_GLOBAL_DEFAULT);
  return result;
}

S lowerAscii(S value) {
  for (char &c : value)
    c = static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  return value;
}

S trim(S value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == S::npos)
    return {};
  return value.substr(first,
                      value.find_last_not_of(" \t\r\n") - first + 1);
}

bool startsWith(const S &value, const S &prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}

bool startsWithI(const S &value, const S &prefix) {
  return startsWith(lowerAscii(value), lowerAscii(prefix));
}

S part(CURLU *url, CURLUPart item, unsigned int flags = 0) {
  char *value = nullptr;
  if (curl_url_get(url, item, &value, flags) != CURLUE_OK)
    return {};
  S result(value ? value : "");
  curl_free(value);
  return result;
}

bool hasPart(CURLU *url, CURLUPart item) {
  char *value = nullptr;
  const auto result = curl_url_get(url, item, &value, 0);
  if (value)
    curl_free(value);
  return result == CURLUE_OK;
}

struct UrlHandle {
  CURLU *value = curl_url();
  ~UrlHandle() {
    if (value)
      curl_url_cleanup(value);
  }
  UrlHandle(const UrlHandle &) = delete;
  UrlHandle &operator=(const UrlHandle &) = delete;
  UrlHandle() = default;
};

S normalizeInput(const S &input, S &error) {
  S value = trim(input);
  if (value.empty()) {
    error = "Enter a website address.";
    return {};
  }
  if (value.size() > 8192) {
    error = "The website address exceeds the 8192-character limit.";
    return {};
  }
  if (value.find_first_of(" \t\r\n\\") != S::npos) {
    error = "Remove spaces and backslashes from the website address.";
    return {};
  }
  if (value.rfind("//", 0) == 0)
    return "https:" + value;
  if (value.find("://") != S::npos)
    return value;

  const auto colon = value.find(':');
  const auto authorityEnd = value.find_first_of("/?#");
  if (colon != S::npos &&
      (authorityEnd == S::npos || colon < authorityEnd) &&
      (value.empty() || value.front() != '[')) {
    const S prefix = value.substr(0, colon);
    const bool looksLikeScheme =
        !prefix.empty() &&
        std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) {
          return std::isalpha(c) != 0;
        }) &&
        lowerAscii(prefix) != "localhost";
    if (looksLikeScheme) {
      error = "Only HTTP and HTTPS website addresses are supported.";
      return {};
    }
  }
  return "https://" + value;
}

bool resolveReference(const S &base, const S &reference, S &absolute) {
  UrlHandle url;
  if (!url.value || curl_url_set(url.value, CURLUPART_URL, base.c_str(), 0) !=
                        CURLUE_OK ||
      curl_url_set(url.value, CURLUPART_URL, reference.c_str(), 0) !=
          CURLUE_OK)
    return false;
  absolute = part(url.value, CURLUPART_URL);
  return !absolute.empty();
}

void addFinding(std::vector<Finding> &findings, const S &id, const S &module,
                const S &severity, const S &text, const S &evidence,
                int points, int reliability = 80, S family = {}) {
  const auto found = std::find_if(
      findings.begin(), findings.end(),
      [&](const Finding &item) { return item.id == id; });
  if (found != findings.end() &&
      found->points * found->reliability >= points * reliability)
    return;
  Finding finding{id, module, family.empty() ? module : std::move(family),
                  severity, text, evidence, points,
                  std::clamp(reliability, 0, 100)};
  if (found == findings.end())
    findings.push_back(std::move(finding));
  else
    *found = std::move(finding);
}

J findingJson(const Finding &finding) {
  return {{"id", finding.id},
          {"module", finding.module},
          {"category", finding.module},
          {"family", finding.family},
          {"severity", finding.severity},
          {"text", finding.text},
          {"evidence", finding.evidence},
          {"points", finding.points},
          {"reliability", finding.reliability}};
}

J findingsJson(const std::vector<Finding> &findings) {
  J result = J::array();
  for (const auto &finding : findings)
    result.push_back(findingJson(finding));
  return result;
}

J check(const S &id, const S &name, const S &status, const S &summary,
        const J &evidence = J::array()) {
  return {{"id", id},
          {"name", name},
          {"status", status},
          {"summary", summary},
          {"evidence", evidence}};
}

J indicatorCoverage() {
  return J::array({
      {{"letter", "A"},
       {"category", "Address and URL structure"},
       {"status", "checked"},
       {"details", "URL validity, scheme, port, IP literals, length, encoding, query shape and subdomain depth."}},
      {{"letter", "B"},
       {"category", "Brand and claimed identity"},
       {"status", "partial"},
       {"details", "A small local brand/domain reference set, common ASCII digit substitutions, and title claims; not proof of brand ownership."}},
      {{"letter", "C"},
       {"category", "Certificate"},
       {"status", "partial"},
       {"details", "TLS verification and certificate expiry are reported when an HTTPS response is reached."}},
      {{"letter", "D"},
       {"category", "DNS"},
       {"status", "partial"},
       {"details", "System-resolver A/AAAA answers and resolver-reported hostname; no authoritative CNAME or registration lookup."}},
      {{"letter", "E"},
       {"category", "External resources"},
       {"status", "partial"},
       {"details", "External links and selected resource hosts are counted; resources are not fetched independently."}},
      {{"letter", "F"},
       {"category", "Forms"},
       {"status", "partial"},
       {"details", "Password/sensitive fields and cross-registered-domain form destinations; ordinary login forms alone are not penalized."}},
      {{"letter", "G"},
       {"category", "Domain age"},
       {"status", "not_checked"},
       {"details", "No registration-date source is queried; age is not inferred."}},
      {{"letter", "H"},
       {"category", "HTTP behavior"},
       {"status", "partial"},
       {"details", "Response status, selected headers, content type, size limits and connection outcomes."}},
      {{"letter", "I"},
       {"category", "IP destinations"},
       {"status", "checked"},
       {"details", "Private/reserved destinations are blocked; public DNS answers are pinned during each request."}},
      {{"letter", "K"},
       {"category", "Keyword context"},
       {"status", "partial"},
       {"details", "Limited visible-text combinations are considered with credential or sensitive-form context."}},
      {{"letter", "L"},
       {"category", "Links and labels"},
       {"status", "partial"},
       {"details", "External links are counted and URL-like visible labels are compared with parsed destinations."}},
      {{"letter", "M"},
       {"category", "Metadata"},
       {"status", "partial"},
       {"details", "Title, selected metadata and meta-refresh destinations are inspected as inert text."}},
      {{"letter", "N"},
       {"category", "Nameservers and registration"},
       {"status", "not_checked"},
       {"details", "Nameserver, registrar and registration records are unavailable in this local-only inspection."}},
      {{"letter", "O"},
       {"category", "Ownership"},
       {"status", "not_checked"},
       {"details", "Domain ownership and official-site status are not independently verified."}},
      {{"letter", "P"},
       {"category", "Ports and protocol"},
       {"status", "checked"},
       {"details", "Only HTTP/80 and HTTPS/443 are contacted; nonstandard ports are not fetched."}},
      {{"letter", "Q"},
       {"category", "Query and navigation parameters"},
       {"status", "partial"},
       {"details", "Query complexity and selected embedded cross-domain navigation targets are observed, not followed."}},
      {{"letter", "R"},
       {"category", "Redirects"},
       {"status", "partial"},
       {"details", "Redirects are followed manually with destination validation, loop checks and a strict hop limit."}},
      {{"letter", "S"},
       {"category", "Subdomains"},
       {"status", "partial"},
       {"details", "Hostname depth and registered-domain relationships use a conservative suffix approximation."}},
      {{"letter", "T"},
       {"category", "Transport security"},
       {"status", "partial"},
       {"details", "TLS certificate and hostname verification are reported; HTTPS is not proof of legitimacy."}},
      {{"letter", "U"},
       {"category", "Unicode hostname"},
       {"status", "partial"},
       {"details", "Punycode presence is surfaced; a complete Unicode confusable/skeleton analysis is not implemented."}},
      {{"letter", "V"},
       {"category", "Visual identity"},
       {"status", "not_checked"},
       {"details", "No screenshot, logo, or visual brand verification is performed."}},
      {{"letter", "W"},
       {"category", "Web content"},
       {"status", "partial"},
       {"details", "Bounded HTML is parsed as text; scripts are never executed and content may be incomplete."}},
      {{"letter", "X"},
       {"category", "External threat intelligence"},
       {"status", "not_used"},
       {"details", "No third-party verdict API, paid service, or external reputation feed is queried."}},
  });
}

void setCheck(J &checks, const S &id, const J &value) {
  for (auto &item : checks)
    if (item.value("id", S()) == id) {
      item = value;
      return;
    }
  checks.push_back(value);
}

S hostForUrl(const S &url) {
  ParsedUrl parsed;
  S error;
  return parseUrl(url, parsed, error) ? parsed.host : S();
}

S relatedHost(const S &left, const S &right) {
  if (left == right || left.empty() || right.empty())
    return left == right ? "same" : "different";
  if (left.size() > right.size() &&
      left.compare(left.size() - right.size(), right.size(), right) == 0 &&
      left[left.size() - right.size() - 1] == '.')
    return "related";
  if (right.size() > left.size() &&
      right.compare(right.size() - left.size(), left.size(), left) == 0 &&
      right[right.size() - left.size() - 1] == '.')
    return "related";
  return "different";
}

S registrableDomain(const S &host) {
  asio::error_code error;
  const auto address = asio::ip::make_address(host, error);
  if (!error)
    return address.to_string();
  std::vector<S> labels;
  std::stringstream stream(host);
  S label;
  while (std::getline(stream, label, '.'))
    labels.push_back(label);
  if (labels.size() < 2)
    return host;

  static const std::set<S> multiLabelSuffixes = {
      "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
      "org.au", "edu.au", "co.nz", "org.nz", "ac.nz", "co.jp",
      "or.jp", "ne.jp", "co.in", "firm.in", "net.in", "org.in",
      "com.br", "com.cn", "com.sg", "com.tr", "com.mx", "com.ar",
      "co.za"};
  const S lastTwo = labels[labels.size() - 2] + "." + labels.back();
  const size_t count =
      labels.size() >= 3 && multiLabelSuffixes.count(lastTwo) ? 3 : 2;
  S result;
  for (size_t i = labels.size() - count; i < labels.size(); ++i) {
    if (!result.empty())
      result += ".";
    result += labels[i];
  }
  return result;
}

bool sameSite(const S &left, const S &right) {
  return registrableDomain(left) == registrableDomain(right);
}

struct Brand {
  S name;
  S root;
  Args domains;
};

const std::vector<Brand> &knownBrands() {
  static const std::vector<Brand> brands = {
      {"Amazon", "amazon",
       {"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.in",
        "amazon.com.au", "amazon.de", "amazon.fr", "amazon.co.jp"}},
      {"Apple", "apple", {"apple.com", "icloud.com"}},
      {"Adobe", "adobe", {"adobe.com"}},
      {"Dropbox", "dropbox", {"dropbox.com"}},
      {"Facebook", "facebook", {"facebook.com", "fb.com", "meta.com"}},
      {"Google", "google",
       {"google.com", "google.co.uk", "google.ca", "google.co.in",
        "google.com.au", "google.de", "google.fr", "google.co.jp"}},
      {"Instagram", "instagram", {"instagram.com"}},
      {"LinkedIn", "linkedin", {"linkedin.com"}},
      {"Microsoft", "microsoft",
       {"microsoft.com", "microsoftonline.com", "live.com", "office.com",
        "outlook.com", "azure.com", "windows.com"}},
      {"Netflix", "netflix", {"netflix.com"}},
      {"PayPal", "paypal",
       {"paypal.com", "paypal.co.uk", "paypal.ca", "paypal.com.au"}},
      {"YouTube", "youtube",
       {"youtube.com", "youtube.co.uk", "youtube.ca", "youtube.in",
        "youtube.com.au", "youtube.de", "youtube.fr", "youtube.co.jp",
        "youtu.be"}}};
  return brands;
}

bool hostIsBrandDomain(const S &host, const Brand &brand) {
  return std::any_of(brand.domains.begin(), brand.domains.end(),
                     [&](const S &domain) {
                       return host == domain ||
                              (host.size() > domain.size() &&
                               host.compare(host.size() - domain.size(),
                                            domain.size(), domain) == 0 &&
                               host[host.size() - domain.size() - 1] == '.');
                     });
}

bool containsToken(const S &text, const S &token) {
  const S value = lowerAscii(text);
  size_t at = value.find(token);
  while (at != S::npos) {
    const bool left = at == 0 ||
                      !std::isalnum(static_cast<unsigned char>(value[at - 1]));
    const size_t end = at + token.size();
    const bool right =
        end == value.size() ||
        !std::isalnum(static_cast<unsigned char>(value[end]));
    if (left && right)
      return true;
    at = value.find(token, at + 1);
  }
  return false;
}

int editDistance(const S &left, const S &right) {
  std::vector<int> row(right.size() + 1);
  for (size_t j = 0; j <= right.size(); ++j)
    row[j] = static_cast<int>(j);
  for (size_t i = 1; i <= left.size(); ++i) {
    int diagonal = row[0];
    row[0] = static_cast<int>(i);
    for (size_t j = 1; j <= right.size(); ++j) {
      const int previous = row[j];
      row[j] = std::min({row[j] + 1, row[j - 1] + 1,
                         diagonal + (left[i - 1] == right[j - 1] ? 0 : 1)});
      diagonal = previous;
    }
  }
  return row.back();
}

S normalizeAsciiConfusables(S value) {
  for (char &c : value) {
    switch (c) {
    case '0':
      c = 'o';
      break;
    case '1':
      c = 'l';
      break;
    case '3':
      c = 'e';
      break;
    case '5':
      c = 's';
      break;
    case '7':
      c = 't';
      break;
    default:
      break;
    }
  }
  return value;
}

bool brandLabelLooksLike(const S &label, const S &brand,
                         bool &characterSubstitution) {
  std::stringstream tokens(label);
  S token;
  while (std::getline(tokens, token, '-')) {
    if (token.empty() || token == brand)
      continue;
    if (normalizeAsciiConfusables(token) == brand) {
      characterSubstitution = true;
      return true;
    }
    if (editDistance(token, brand) <= (brand.size() >= 8 ? 2 : 1))
      return true;
  }
  return false;
}

S decodePercent(const S &value) {
  const auto hexValue = [](char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  S decoded;
  decoded.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      const int high = hexValue(value[i + 1]);
      const int low = hexValue(value[i + 2]);
      if (high >= 0 && low >= 0) {
        decoded += static_cast<char>((high << 4) | low);
        i += 2;
        continue;
      }
    }
    decoded += value[i];
  }
  return decoded;
}

S registrableLabel(const S &host) {
  const S domain = registrableDomain(host);
  const auto dot = domain.find('.');
  return dot == S::npos ? domain : domain.substr(0, dot);
}

bool isHtmlType(const S &contentType) {
  const S type = lowerAscii(contentType);
  return startsWith(type, "text/html") ||
         startsWith(type, "application/xhtml+xml");
}

struct ResolveState {
  asio::error_code error;
  asio::ip::tcp::resolver::results_type results;
  bool done = false;
};

struct Resolution {
  bool ok = false;
  bool timedOut = false;
  bool blocked = false;
  bool definitivelyMissing = false;
  S message;
  S canonicalName;
  std::vector<S> addresses;
  std::vector<S> ipv4;
  std::vector<S> ipv6;
};

Resolution resolvePublic(const ParsedUrl &url,
                        const Clock::time_point &deadline) {
  Resolution result;
  asio::error_code addressError;
  const auto literal = asio::ip::make_address(url.host, addressError);
  if (!addressError) {
    const S address = literal.to_string();
    if (!isPublicAddress(address)) {
      result.blocked = true;
      result.message =
          "The destination resolves to a loopback, private, reserved, or "
          "link-local address and was blocked.";
      return result;
    }
    result.ok = true;
    result.addresses.push_back(address);
    if (literal.is_v4())
      result.ipv4.push_back(address);
    else
      result.ipv6.push_back(address);
    return result;
  }

  const S host = lowerAscii(url.host);
  for (const S &suffix :
       Args{".localhost", ".local", ".internal", ".test", ".invalid",
            ".example", ".home.arpa"}) {
    if (host == suffix.substr(1) ||
        (host.size() > suffix.size() &&
         host.compare(host.size() - suffix.size(), suffix.size(), suffix) ==
             0)) {
      result.blocked = true;
      result.message =
          "Local and reserved hostnames are not inspected by the scanner.";
      return result;
    }
  }
  if (host == "localhost") {
    result.blocked = true;
    result.message =
        "Local and reserved hostnames are not inspected by the scanner.";
    return result;
  }
  if (url.host.find('%') != S::npos) {
    result.blocked = true;
    result.message = "Scoped IP addresses are not inspected.";
    return result;
  }
  const auto remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                            Clock::now());
  if (remaining <= std::chrono::milliseconds::zero()) {
    result.timedOut = true;
    result.message = "The scan time budget expired during DNS resolution.";
    return result;
  }

  asio::io_context context;
  asio::ip::tcp::resolver resolver(context);
  auto state = std::make_shared<ResolveState>();
  const S absoluteHost =
      !url.host.empty() && url.host.back() == '.' ? url.host : url.host + ".";
  resolver.async_resolve(
      absoluteHost, url.port,
      [state](const asio::error_code &error,
              const asio::ip::tcp::resolver::results_type &records) {
        state->error = error;
        state->results = records;
        state->done = true;
      });

  const auto wait = std::min(remaining, std::chrono::milliseconds(1500));
  context.run_for(wait);
  if (!state->done) {
    resolver.cancel();
    context.restart();
    context.poll();
    result.timedOut = true;
    result.message = "DNS resolution timed out.";
    return result;
  }
  if (state->error) {
    result.definitivelyMissing =
        state->error == asio::error::host_not_found ||
        state->error == asio::error::no_data;
    result.message = result.definitivelyMissing
                         ? "DNS returned no address records."
                         : "The operating-system DNS resolver failed.";
    return result;
  }

  for (const auto &record : state->results) {
    const auto address = record.endpoint().address();
    const S text = address.to_string();
    if (!isPublicAddress(text)) {
      result.blocked = true;
      result.message =
          "At least one DNS answer is loopback, private, reserved, or "
          "link-local; the destination was blocked.";
      result.addresses.clear();
      result.ipv4.clear();
      result.ipv6.clear();
      return result;
    }
    if (std::find(result.addresses.begin(), result.addresses.end(), text) ==
        result.addresses.end()) {
      result.addresses.push_back(text);
      if (address.is_v4())
        result.ipv4.push_back(text);
      else
        result.ipv6.push_back(text);
    }
    if (result.canonicalName.empty() &&
        !record.host_name().empty() &&
        lowerAscii(record.host_name()) != lowerAscii(url.host))
      result.canonicalName = record.host_name();
  }
  result.ok = !result.addresses.empty();
  if (!result.ok)
    result.message = "DNS returned no usable address records.";
  return result;
}

struct Transfer {
  long status = 0;
  long tlsVerifyResult = 0;
  CURLcode curlStatus = CURLE_OK;
  S error;
  S body;
  std::map<S, S> headers;
  S certificateExpiry;
  bool truncated = false;
  bool headersTruncated = false;
  bool transportIncomplete = false;
  size_t headerBytes = 0;
};

size_t receiveBody(char *data, size_t size, size_t count, void *context) {
  auto &transfer = *static_cast<Transfer *>(context);
  if (count && size > std::numeric_limits<size_t>::max() / count)
    return 0;
  const size_t bytes = size * count;
  const size_t remaining =
      transfer.body.size() < MaxBodyBytes
          ? MaxBodyBytes - transfer.body.size()
          : 0;
  const size_t accepted = std::min(bytes, remaining);
  transfer.body.append(data, accepted);
  if (accepted != bytes) {
    transfer.truncated = true;
    return 0;
  }
  return bytes;
}

bool wantedHeader(const S &name) {
  static const std::set<S> allowed = {
      "content-type",          "content-length",
      "server",                "location",
      "strict-transport-security", "content-security-policy",
      "x-content-type-options", "x-frame-options",
      "referrer-policy",       "date"};
  return allowed.count(name) != 0;
}

size_t receiveHeader(char *data, size_t size, size_t count, void *context) {
  auto &transfer = *static_cast<Transfer *>(context);
  if (count && size > std::numeric_limits<size_t>::max() / count)
    return 0;
  const size_t bytes = size * count;
  if (bytes > MaxHeaderBytes - std::min(MaxHeaderBytes, transfer.headerBytes)) {
    transfer.headersTruncated = true;
    return 0;
  }
  transfer.headerBytes += bytes;
  const S line(data, bytes);
  if (startsWithI(line, "HTTP/")) {
    transfer.headers.clear();
    return bytes;
  }
  const auto colon = line.find(':');
  if (colon == S::npos)
    return bytes;
  const S name = lowerAscii(trim(line.substr(0, colon)));
  if (wantedHeader(name)) {
    S value = trim(line.substr(colon + 1));
    const size_t limit = name == "location" ? 4096 : 1024;
    if (value.size() > limit)
      value.resize(limit);
    transfer.headers[name] = std::move(value);
  }
  return bytes;
}

template <typename Value>
void setOption(CURL *handle, CURLoption option, Value value) {
  if (curl_easy_setopt(handle, option, value) != CURLE_OK)
    throw std::runtime_error("Could not configure the local website request.");
}

S resolveEntry(const ParsedUrl &url, const std::vector<S> &addresses) {
  S entry = url.host + ":" + url.port + ":";
  for (const S &address : addresses) {
    if (!entry.empty() && entry.back() != ':')
      entry += ",";
    entry += address.find(':') == S::npos ? address : "[" + address + "]";
  }
  return entry;
}

Transfer requestPage(const ParsedUrl &url, const Resolution &resolution,
                     int timeoutMs) {
  if (initializeCurl() != CURLE_OK)
    throw std::runtime_error("The local HTTP inspection engine is unavailable.");
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(
      curl_easy_init(), curl_easy_cleanup);
  if (!handle)
    throw std::runtime_error("The local HTTP inspection engine is unavailable.");

  Transfer transfer;
  char errorBuffer[CURL_ERROR_SIZE] = {};
  curl_slist *resolveRows = nullptr;
  curl_slist *headers = nullptr;
  const auto append = [](curl_slist *&list, const S &value) {
    curl_slist *next = curl_slist_append(list, value.c_str());
    if (!next)
      throw std::runtime_error("Could not allocate HTTP request headers.");
    list = next;
  };
  try {
    if (!url.isIp)
      append(resolveRows, resolveEntry(url, resolution.addresses));
    append(headers, "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.1");
    append(headers, "Connection: close");
    setOption(handle.get(), CURLOPT_URL, url.url.c_str());
    setOption(handle.get(), CURLOPT_HTTPHEADER, headers);
    setOption(handle.get(), CURLOPT_RESOLVE, resolveRows);
    setOption(handle.get(), CURLOPT_USERAGENT,
              "CyberShield local website inspector/1.0");
    setOption(handle.get(), CURLOPT_HTTPGET, 1L);
    setOption(handle.get(), CURLOPT_FOLLOWLOCATION, 0L);
    setOption(handle.get(), CURLOPT_MAXREDIRS, 0L);
    setOption(handle.get(), CURLOPT_PROTOCOLS,
              static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    setOption(handle.get(), CURLOPT_PROXY, "");
    setOption(handle.get(), CURLOPT_NOPROXY, "*");
    setOption(handle.get(), CURLOPT_NETRC, CURL_NETRC_IGNORED);
    setOption(handle.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    setOption(handle.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    setOption(handle.get(), CURLOPT_CERTINFO, 1L);
    setOption(handle.get(), CURLOPT_CONNECTTIMEOUT_MS,
              static_cast<long>(std::min(timeoutMs, 2500)));
    setOption(handle.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(timeoutMs));
    setOption(handle.get(), CURLOPT_NOSIGNAL, 1L);
    setOption(handle.get(), CURLOPT_LOW_SPEED_LIMIT, 32L);
    setOption(handle.get(), CURLOPT_LOW_SPEED_TIME, 3L);
    setOption(handle.get(), CURLOPT_MAXFILESIZE_LARGE,
              static_cast<curl_off_t>(MaxBodyBytes));
    setOption(handle.get(), CURLOPT_ACCEPT_ENCODING, "");
    setOption(handle.get(), CURLOPT_ERRORBUFFER, errorBuffer);
    setOption(handle.get(), CURLOPT_WRITEFUNCTION, receiveBody);
    setOption(handle.get(), CURLOPT_WRITEDATA, &transfer);
    setOption(handle.get(), CURLOPT_HEADERFUNCTION, receiveHeader);
    setOption(handle.get(), CURLOPT_HEADERDATA, &transfer);
#ifdef _WIN32
    const auto ca = root / "windows-x64/ca-bundle.crt";
    if (std::filesystem::exists(ca)) {
      const S caPath = ca.u8string();
      setOption(handle.get(), CURLOPT_CAINFO, caPath.c_str());
    }
#endif

    transfer.curlStatus = curl_easy_perform(handle.get());
    curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &transfer.status);
    if (transfer.curlStatus == CURLE_FILESIZE_EXCEEDED)
      transfer.truncated = true;
    if (transfer.curlStatus != CURLE_OK && !transfer.truncated &&
        !transfer.headersTruncated)
      transfer.transportIncomplete = true;
    curl_easy_getinfo(handle.get(), CURLINFO_SSL_VERIFYRESULT,
                      &transfer.tlsVerifyResult);
    if (transfer.curlStatus != CURLE_OK && errorBuffer[0])
      transfer.error = errorBuffer;
    else if (transfer.curlStatus != CURLE_OK)
      transfer.error = curl_easy_strerror(transfer.curlStatus);

    struct curl_certinfo *certificates = nullptr;
    if (curl_easy_getinfo(handle.get(), CURLINFO_CERTINFO, &certificates) ==
            CURLE_OK &&
        certificates) {
      for (int i = 0; i < certificates->num_of_certs; ++i) {
        for (auto *item = certificates->certinfo[i]; item; item = item->next) {
          const S line = item->data ? item->data : "";
          if (startsWithI(line, "Expire date:")) {
            transfer.certificateExpiry = trim(line.substr(12));
            break;
          }
        }
        if (!transfer.certificateExpiry.empty())
          break;
      }
    }
  } catch (...) {
    curl_slist_free_all(headers);
    curl_slist_free_all(resolveRows);
    throw;
  }
  curl_slist_free_all(headers);
  curl_slist_free_all(resolveRows);
  return transfer;
}

bool redirectStatus(long status) {
  return status == 301 || status == 302 || status == 303 || status == 307 ||
         status == 308;
}

S curlFailure(const Transfer &transfer) {
  if (transfer.curlStatus == CURLE_PEER_FAILED_VERIFICATION &&
      transfer.tlsVerifyResult == X509_V_ERR_CERT_HAS_EXPIRED)
    return "The TLS certificate has expired.";
#ifdef X509_V_ERR_HOSTNAME_MISMATCH
  if (transfer.curlStatus == CURLE_PEER_FAILED_VERIFICATION &&
      transfer.tlsVerifyResult == X509_V_ERR_HOSTNAME_MISMATCH)
    return "The TLS certificate does not match this hostname.";
#endif
  if (transfer.curlStatus == CURLE_PEER_FAILED_VERIFICATION)
    return "TLS certificate verification failed for this hostname.";
  if (transfer.curlStatus == CURLE_OPERATION_TIMEDOUT)
    return "The connection timed out.";
  if (transfer.curlStatus == CURLE_COULDNT_RESOLVE_HOST)
    return "The destination hostname could not be resolved.";
  if (transfer.error.empty())
    return "The website connection failed.";
  return transfer.error.substr(0, 240);
}

S titleText(const S &html) {
  const S lower = lowerAscii(html);
  const auto start = lower.find("<title");
  if (start == S::npos)
    return {};
  const auto open = lower.find('>', start);
  if (open == S::npos)
    return {};
  const auto end = lower.find("</title", open + 1);
  if (end == S::npos)
    return {};
  S value;
  bool insideTag = false;
  for (size_t i = open + 1; i < end && value.size() < 200; ++i) {
    if (html[i] == '<')
      insideTag = true;
    else if (html[i] == '>')
      insideTag = false;
    else if (!insideTag)
      value += html[i];
  }
  return trim(value);
}

S visibleText(const S &html) {
  S text;
  bool insideTag = false;
  S currentTag;
  S skipTag;
  const S lower = lowerAscii(html);
  for (size_t i = 0; i < html.size() && text.size() < 128 * 1024; ++i) {
    if (!skipTag.empty()) {
      if (html[i] == '<' &&
          lower.compare(i, skipTag.size() + 2, "</" + skipTag) == 0) {
        const auto end = lower.find('>', i);
        if (end == S::npos)
          break;
        i = end;
        skipTag.clear();
      }
      continue;
    }
    if (html[i] == '<') {
      insideTag = true;
      currentTag.clear();
    } else if (html[i] == '>' && insideTag) {
      insideTag = false;
      currentTag = lowerAscii(trim(currentTag));
      if (startsWith(currentTag, "script") ||
          startsWith(currentTag, "style"))
        skipTag = startsWith(currentTag, "script") ? "script" : "style";
    } else if (insideTag) {
      if (currentTag.size() < 16)
        currentTag += html[i];
    } else if (html[i] != '\r' && html[i] != '\n')
      text += html[i];
  }
  return lowerAscii(text);
}

std::pair<S, std::map<S, S>> parseTag(const S &tag) {
  size_t at = 0;
  while (at < tag.size() &&
         std::isspace(static_cast<unsigned char>(tag[at])))
    ++at;
  if (at < tag.size() && tag[at] == '/')
    ++at;
  const size_t nameStart = at;
  while (at < tag.size() &&
         (std::isalnum(static_cast<unsigned char>(tag[at])) ||
          tag[at] == '-' || tag[at] == ':'))
    ++at;
  if (at == nameStart)
    return {};
  const S name = lowerAscii(tag.substr(nameStart, at - nameStart));
  std::map<S, S> attributes;
  while (at < tag.size()) {
    while (at < tag.size() &&
           (std::isspace(static_cast<unsigned char>(tag[at])) ||
            tag[at] == '/'))
      ++at;
    const size_t keyStart = at;
    while (at < tag.size() &&
           !std::isspace(static_cast<unsigned char>(tag[at])) &&
           tag[at] != '=' && tag[at] != '/' && tag[at] != '>')
      ++at;
    if (at == keyStart) {
      ++at;
      continue;
    }
    const S key = lowerAscii(tag.substr(keyStart, at - keyStart));
    while (at < tag.size() &&
           std::isspace(static_cast<unsigned char>(tag[at])))
      ++at;
    S value;
    if (at < tag.size() && tag[at] == '=') {
      ++at;
      while (at < tag.size() &&
             std::isspace(static_cast<unsigned char>(tag[at])))
        ++at;
      if (at < tag.size() && (tag[at] == '"' || tag[at] == '\'')) {
        const char quote = tag[at++];
        const size_t valueStart = at;
        while (at < tag.size() && tag[at] != quote)
          ++at;
        value = tag.substr(valueStart, at - valueStart);
        if (at < tag.size())
          ++at;
      } else {
        const size_t valueStart = at;
        while (at < tag.size() &&
               !std::isspace(static_cast<unsigned char>(tag[at])) &&
               tag[at] != '>')
          ++at;
        value = tag.substr(valueStart, at - valueStart);
      }
    }
    if (value.size() > 4096)
      value.resize(4096);
    attributes.emplace(key, std::move(value));
  }
  return {name, attributes};
}

struct FormInfo {
  bool password = false;
  bool external = false;
  bool unresolved = false;
  int sensitiveFields = 0;
  S actionHost;
};

struct FormDestination {
  bool external = false;
  bool resolved = true;
  S host;
};

FormDestination formDestination(const S &baseUrl, const S &action) {
  if (action.empty())
    return {};
  S absolute;
  if (!resolveReference(baseUrl, action, absolute))
    return {false, false, {}};
  ParsedUrl parsed;
  S error;
  if (!parseUrl(absolute, parsed, error))
    return {false, false, {}};
  const S baseHost = hostForUrl(baseUrl);
  return {!sameSite(baseHost, parsed.host), true, parsed.host};
}
}

bool parseUrl(const S &input, ParsedUrl &parsed, S &error) {
  if (initializeCurl() != CURLE_OK) {
    error = "The URL parser is unavailable.";
    return false;
  }
  const S normalized = normalizeInput(input, error);
  if (normalized.empty())
    return false;
  UrlHandle url;
  if (!url.value) {
    error = "The URL parser is unavailable.";
    return false;
  }
  const CURLUcode parsedResult =
      curl_url_set(url.value, CURLUPART_URL, normalized.c_str(), 0);
  if (parsedResult != CURLUE_OK) {
    error = "Enter a valid HTTP or HTTPS website address.";
    return false;
  }

  const S scheme = lowerAscii(part(url.value, CURLUPART_SCHEME));
  S host = lowerAscii(part(url.value, CURLUPART_HOST));
  if (scheme != "http" && scheme != "https") {
    error = "Only HTTP and HTTPS website addresses are supported.";
    return false;
  }
  if (host.empty()) {
    error = "The website address does not contain a hostname.";
    return false;
  }
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
    host = host.substr(1, host.size() - 2);
  if (!host.empty() && host.back() == '.')
    host.pop_back();
  if (host.empty() || host.size() > 253) {
    error = "The hostname length is invalid.";
    return false;
  }

  const bool hasUserInfo = hasPart(url.value, CURLUPART_USER) ||
                           hasPart(url.value, CURLUPART_PASSWORD);
  if (hasUserInfo) {
    curl_url_set(url.value, CURLUPART_USER, nullptr, 0);
    curl_url_set(url.value, CURLUPART_PASSWORD, nullptr, 0);
  }
  if (curl_url_set(url.value, CURLUPART_HOST, host.c_str(), 0) != CURLUE_OK) {
    error = "The hostname could not be normalized.";
    return false;
  }

  const S port = part(url.value, CURLUPART_PORT, CURLU_DEFAULT_PORT);
  if (port.empty() ||
      !std::all_of(port.begin(), port.end(),
                   [](unsigned char c) { return std::isdigit(c) != 0; })) {
    error = "The website address contains an invalid port.";
    return false;
  }
  try {
    const unsigned long value = std::stoul(port);
    if (value == 0 || value > 65535)
      throw std::out_of_range("port");
  } catch (const std::exception &) {
    error = "The website address contains an invalid port.";
    return false;
  }

  asio::error_code addressError;
  const auto address = asio::ip::make_address(host, addressError);
  const bool isIp = !addressError;
  if (!isIp) {
    if (host.find_first_of(",:[]%") != S::npos) {
      error = "Use a valid DNS hostname or IP address.";
      return false;
    }
    for (const S &label : [&] {
           std::vector<S> labels;
           std::stringstream stream(host);
           S label;
           while (std::getline(stream, label, '.'))
             labels.push_back(label);
           return labels;
         }()) {
      if (label.empty() || label.size() > 63 || label.front() == '-' ||
          label.back() == '-' ||
          !std::all_of(label.begin(), label.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '-';
          })) {
        error = "Use a valid DNS hostname; enter international domains in "
                "punycode form.";
        return false;
      }
    }
  }

  parsed.url = part(url.value, CURLUPART_URL);
  parsed.scheme = scheme;
  parsed.host = host;
  parsed.port = port;
  parsed.path = part(url.value, CURLUPART_PATH);
  parsed.isIp = isIp;
  parsed.hasUserInfo = hasUserInfo;
  if (parsed.url.empty()) {
    error = "The website address could not be normalized.";
    return false;
  }
  return true;
}

bool isPublicAddress(const S &text) {
  asio::error_code error;
  const auto address = asio::ip::make_address(text, error);
  if (error || address.is_unspecified() || address.is_loopback() ||
      address.is_multicast())
    return false;
  if (address.is_v4()) {
    const auto bytes = address.to_v4().to_bytes();
    const unsigned a = bytes[0], b = bytes[1], c = bytes[2];
    if (a == 0 || a == 10 || a == 127 || a >= 224)
      return false;
    if (a == 100 && (b & 0xC0) == 0x40)
      return false;
    if (a == 169 && b == 254)
      return false;
    if (a == 172 && b >= 16 && b <= 31)
      return false;
    if (a == 192 &&
        ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99) ||
         b == 168))
      return false;
    if (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
      return false;
    if (a == 203 && b == 0 && c == 113)
      return false;
    return true;
  }

  const auto bytes = address.to_v6().to_bytes();
  const bool globalUnicast = (bytes[0] & 0xE0) == 0x20;
  if (!globalUnicast)
    return false;
  if (bytes[0] == 0x20 && bytes[1] == 0x01 &&
      (bytes[2] & 0xFE) == 0x00)
    return false;
  if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D &&
      bytes[3] == 0xB8)
    return false;
  if (bytes[0] == 0x20 && bytes[1] == 0x02)
    return false;
  return true;
}

ScoreResult scoreFindings(const std::vector<Finding> &findings) {
  static const std::map<S, int> categoryCaps = {
      {"url", 26},       {"identity", 55}, {"content", 30},
      {"forms", 40},     {"links", 20},    {"redirect", 22},
      {"tls", 12},       {"http", 10},     {"dns", 8},
      {"tld", config::UnapprovedTldRiskPoints},
      {"denylist", 100}};
  std::map<S, const Finding *> unique;
  for (const auto &finding : findings) {
    const auto found = unique.find(finding.id);
    if (finding.points <= 0 || finding.reliability <= 0)
      continue;
    if (found == unique.end() ||
        finding.points * finding.reliability >
            found->second->points * found->second->reliability)
      unique[finding.id] = &finding;
  }
  std::map<S, std::map<S, std::vector<int>>> evidence;
  for (const auto &item : unique) {
    const auto &finding = *item.second;
    const S family = finding.family.empty() ? finding.module : finding.family;
    const int weighted =
        (std::min(finding.points, 100) *
             std::min(std::max(finding.reliability, 0), 100) +
         50) /
        100;
    if (weighted > 0)
      evidence[finding.module][family].push_back(weighted);
  }

  ScoreResult result;
  for (auto &module : evidence) {
    int contribution = 0;
    for (auto &family : module.second) {
      auto &values = family.second;
      std::sort(values.begin(), values.end(), std::greater<int>());
      contribution += values.front();
      if (values.size() > 1)
        contribution += (values[1] + 2) / 4;
    }
    const auto cap = categoryCaps.find(module.first);
    result.categoryPoints[module.first] =
        std::min(contribution, cap == categoryCaps.end() ? 20 : cap->second);
  }

  int total = 0;
  for (const auto &category : result.categoryPoints) {
    total += category.second;
    if (category.second >= 10)
      ++result.independentCategories;
  }
  result.categorySubtotal = total;
  result.corroborationBonus =
      std::min(12, std::max(0, result.independentCategories - 1) * 4);
  result.score =
      std::min(100, result.categorySubtotal + result.corroborationBonus);
  return result;
}

J inspectHtml(const S &html, const S &baseUrl) {
  J output = {{"title", titleText(html)},
              {"metadata", J::array()},
              {"forms", 0},
              {"password_forms", 0},
              {"external_forms", 0},
              {"sensitive_forms", 0},
              {"external_links", 0},
              {"external_resources", 0},
              {"meta_refresh", ""},
              {"unresolved_forms", 0},
              {"complete", true},
              {"notes", J::array()},
              {"findings", J::array()}};
  const S visible = visibleText(html);
  std::vector<Finding> findings;
  std::vector<FormInfo> forms;
  FormInfo current;
  bool inForm = false;
  bool inAnchor = false;
  S anchorHref, anchorText;
  int externalLinks = 0;
  int externalResources = 0;
  S metaRefresh;
  J linkEvidence = J::array();
  size_t scannedTags = 0;
  bool tagLimitReached = false;
  const auto inspectAnchor = [&]() {
    if (anchorHref.empty())
      return;
    S absolute;
    ParsedUrl destination;
    S error;
    if (!resolveReference(baseUrl, anchorHref, absolute) ||
        !parseUrl(absolute, destination, error))
      return;
    if (!sameSite(hostForUrl(baseUrl), destination.host)) {
      ++externalLinks;
      if (linkEvidence.size() < 64)
        linkEvidence.push_back("External link destination: " +
                               destination.host);
    }

    const S lowerLabel = lowerAscii(anchorText);
    auto labelAt = lowerLabel.find("https://");
    size_t prefixLength = 8;
    if (labelAt == S::npos) {
      labelAt = lowerLabel.find("http://");
      prefixLength = 7;
    }
    if (labelAt == S::npos) {
      labelAt = lowerLabel.find("www.");
      prefixLength = 0;
    }
    if (labelAt != S::npos) {
      S claimed = trim(anchorText.substr(labelAt));
      const auto end = claimed.find_first_of(" \t\r\n<>\"'");
      if (end != S::npos)
        claimed.resize(end);
      while (!claimed.empty() &&
             std::string(".,;:!?)]}").find(claimed.back()) != S::npos)
        claimed.pop_back();
      if (prefixLength == 0)
        claimed = "https://" + claimed;
      ParsedUrl claimedDestination;
      if (parseUrl(claimed, claimedDestination, error) &&
          !sameSite(destination.host, claimedDestination.host)) {
        addFinding(findings, "mismatched_link_label", "links", "moderate",
                   "A link's visible URL-like label points to a different "
                   "registered domain than its destination.",
                   "Visible label domain: " +
                       registrableDomain(claimedDestination.host) +
                       "; actual destination domain: " +
                       registrableDomain(destination.host),
                   16, 75, "link_destination");
      }
    }
  };

  for (size_t i = 0; i < html.size() && scannedTags < 20000;) {
    const auto open = html.find('<', i);
    if (open == S::npos)
      break;
    if (inAnchor && open > i && anchorText.size() < 512) {
      anchorText += html.substr(
          i, std::min(open - i, static_cast<size_t>(512 - anchorText.size())));
    }
    if (html.compare(open, 4, "<!--") == 0) {
      const auto end = html.find("-->", open + 4);
      if (end == S::npos)
        break;
      i = end + 3;
      continue;
    }
    char quote = 0;
    size_t end = open + 1;
    for (; end < html.size(); ++end) {
      const char c = html[end];
      if (quote) {
        if (c == quote)
          quote = 0;
      } else if (c == '"' || c == '\'')
        quote = c;
      else if (c == '>')
        break;
    }
    if (end == html.size())
      break;
    ++scannedTags;
    if (end - open > 4096) {
      tagLimitReached = true;
      i = end + 1;
      continue;
    }
    const S rawTag = html.substr(open + 1, end - open - 1);
    const S trimmedTag = trim(rawTag);
    const bool closing = !trimmedTag.empty() && trimmedTag.front() == '/';
    const auto parsedTag = parseTag(rawTag);
    const S name = parsedTag.first;
    const auto &attributes = parsedTag.second;
    if (closing && name == "form" && inForm) {
      if (forms.size() < 128)
        forms.push_back(current);
      else
        tagLimitReached = true;
      current = {};
      inForm = false;
    } else if (closing && name == "a" && inAnchor) {
      inspectAnchor();
      anchorHref.clear();
      anchorText.clear();
      inAnchor = false;
    } else if (!closing && name == "form") {
      if (inForm && forms.size() < 128)
        forms.push_back(current);
      current = {};
      inForm = true;
      const auto action = attributes.find("action");
      if (action != attributes.end()) {
        const auto destination = formDestination(baseUrl, action->second);
        current.external = destination.external;
        current.unresolved = !destination.resolved;
        current.actionHost = destination.host;
      }
    } else if (!closing && name == "a") {
      const auto href = attributes.find("href");
      anchorHref = href == attributes.end() ? S() : href->second;
      anchorText.clear();
      inAnchor = true;
    } else if (!closing && name == "input" && inForm) {
      const auto type = attributes.find("type");
      const S inputType =
          type == attributes.end() ? S() : lowerAscii(type->second);
      if (inputType == "password") {
        current.password = true;
        ++current.sensitiveFields;
      } else if (inputType == "email" || inputType == "tel" ||
                 inputType == "number") {
        ++current.sensitiveFields;
      }
      const auto nameAttribute = attributes.find("name");
      const auto autocomplete = attributes.find("autocomplete");
      const S fieldName =
          nameAttribute == attributes.end() ? S()
                                            : lowerAscii(nameAttribute->second);
      const S autoComplete =
          autocomplete == attributes.end()
              ? S()
              : lowerAscii(autocomplete->second);
      if (fieldName.find("card") != S::npos ||
          fieldName.find("cvv") != S::npos ||
          fieldName.find("ssn") != S::npos ||
          fieldName.find("bank") != S::npos ||
          autoComplete == "cc-number" || autoComplete == "cc-csc" ||
          autoComplete == "current-password" ||
          autoComplete == "one-time-code")
        ++current.sensitiveFields;
    } else if (!closing &&
               (name == "img" || name == "script" || name == "iframe" ||
                name == "link")) {
      const auto source = attributes.find(name == "link" ? "href" : "src");
      if (source != attributes.end()) {
        S absolute;
        ParsedUrl destination;
        S error;
        if (resolveReference(baseUrl, source->second, absolute) &&
            parseUrl(absolute, destination, error) &&
            !sameSite(hostForUrl(baseUrl), destination.host))
          ++externalResources;
      }
    } else if (!closing && name == "meta") {
      const auto nameAttribute = attributes.find("name");
      const auto propertyAttribute = attributes.find("property");
      const auto contentAttribute = attributes.find("content");
      const auto httpEquiv = attributes.find("http-equiv");
      if (contentAttribute != attributes.end() &&
          httpEquiv != attributes.end() &&
          lowerAscii(httpEquiv->second) == "refresh") {
        const S refresh = lowerAscii(contentAttribute->second);
        const auto urlAt = refresh.find("url=");
        if (urlAt != S::npos) {
          S reference = trim(contentAttribute->second.substr(urlAt + 4));
          if (reference.size() >= 2 &&
              ((reference.front() == '\'' && reference.back() == '\'') ||
               (reference.front() == '"' && reference.back() == '"')))
            reference = reference.substr(1, reference.size() - 2);
          S absolute;
          ParsedUrl destination;
          S error;
          if (resolveReference(baseUrl, reference, absolute) &&
              parseUrl(absolute, destination, error)) {
            metaRefresh = destination.host;
            if (!sameSite(hostForUrl(baseUrl), destination.host))
              addFinding(findings, "cross_domain_meta_refresh", "redirect",
                         "moderate",
                         "The page declares a client-side refresh to an "
                         "unrelated registered domain.",
                         "Refresh destination hostname: " + destination.host,
                         12, 72, "client_redirect");
          }
        }
      }
      const S metadataName =
          nameAttribute != attributes.end()
              ? lowerAscii(nameAttribute->second)
              : propertyAttribute != attributes.end()
                    ? lowerAscii(propertyAttribute->second)
                    : S();
      if (contentAttribute != attributes.end() &&
          (metadataName == "description" || metadataName == "og:title" ||
           metadataName == "og:site_name")) {
        S content = trim(contentAttribute->second);
        if (content.size() > 200)
          content.resize(200);
        output["metadata"].push_back(
            {{"name", metadataName}, {"content", content}});
      }
    }
    i = end + 1;
  }
  if (inAnchor)
    inspectAnchor();
  if (inForm && forms.size() < 128)
    forms.push_back(current);
  if (scannedTags >= 20000)
    tagLimitReached = true;

  int passwordForms = 0;
  int externalPasswordForms = 0;
  int externalForms = 0;
  int sensitiveForms = 0;
  int unresolvedForms = 0;
  const S baseHost = hostForUrl(baseUrl);
  for (const auto &form : forms) {
    passwordForms += form.password ? 1 : 0;
    externalPasswordForms += form.external && form.password ? 1 : 0;
    externalForms += form.external ? 1 : 0;
    sensitiveForms += form.sensitiveFields > 0 ? 1 : 0;
    unresolvedForms += form.unresolved ? 1 : 0;
    if (form.external && form.password) {
      addFinding(findings, "external_password_form", "forms", "high",
                 "A password form submits to a different registered domain.",
                 "Page hostname: " + baseHost +
                     "; form destination hostname: " + form.actionHost,
                 28, 90, "form_destination");
    } else if (form.external && form.sensitiveFields >= 3) {
      addFinding(findings, "external_sensitive_form", "forms", "moderate",
                 "A form with multiple sensitive fields submits to a "
                 "different registered domain.",
                 "Page hostname: " + baseHost +
                     "; form destination hostname: " + form.actionHost +
                     "; sensitive fields observed: " +
                     std::to_string(form.sensitiveFields),
                 18, 75, "form_destination");
    } else if (form.external) {
      addFinding(findings, "external_form", "forms", "low",
                 "A form submits to a different registered domain; this can "
                 "be legitimate but merits contextual review.",
                 "Page hostname: " + baseHost +
                     "; form destination hostname: " + form.actionHost,
                 8, 60, "form_destination");
    }
  }
  const S title = output.value("title", S());
  std::istringstream titleWords(title);
  S titleWord;
  while (titleWords >> titleWord) {
    while (!titleWord.empty() &&
           std::string("([{\"'").find(titleWord.front()) != S::npos)
      titleWord.erase(titleWord.begin());
    while (!titleWord.empty() &&
           std::string(".,;:!?)]}\"'").find(titleWord.back()) != S::npos)
      titleWord.pop_back();
    const auto lastDot = titleWord.rfind('.');
    if (lastDot == S::npos || titleWord.size() - lastDot < 3)
      continue;
    const S suffix = titleWord.substr(lastDot + 1);
    if (!std::all_of(suffix.begin(), suffix.end(), [](unsigned char c) {
          return std::isalpha(c) != 0;
        }))
      continue;
    ParsedUrl mentioned;
    S error;
    if (parseUrl("https://" + titleWord, mentioned, error) &&
        !mentioned.isIp && !sameSite(baseHost, mentioned.host)) {
      addFinding(findings, "title_hostname_mismatch", "content",
                 passwordForms ? "moderate" : "observation",
                 "The page title references a hostname different from the "
                 "page's hostname.",
                 "Page hostname: " + baseHost +
                     "; hostname referenced in title: " + mentioned.host,
                 passwordForms ? 12 : 0);
      break;
    }
    for (const auto &brand : knownBrands()) {
      const bool titleMentionsBrand =
          containsToken(title, brand.name) || containsToken(title, brand.root);
      const bool claimsAccountAccess =
          containsToken(title, "login") || containsToken(title, "sign in") ||
          containsToken(title, "verify") || containsToken(title, "account") ||
          containsToken(title, "official") || containsToken(title, "support") ||
          containsToken(title, "password");
      if (titleMentionsBrand && claimsAccountAccess &&
          !hostIsBrandDomain(baseHost, brand)) {
        addFinding(findings, "claimed_brand_hostname_mismatch", "identity",
                   passwordForms ? "moderate" : "low",
                   "The page title combines a known brand with an account or "
                   "support claim, but the hostname is not in the local list of "
                   "that brand's recognized domains.",
                   "Page title: " + title + "; page hostname: " + baseHost +
                       "; brand reference: " + brand.name + ".",
                   passwordForms ? 18 : 12, 72, "claimed_identity");
        break;
      }
    }
  }
  if (passwordForms)
    output["notes"].push_back(
        std::to_string(passwordForms) +
        " password form(s) found. Login forms alone are not evidence of "
        "malicious behavior.");
  if (unresolvedForms)
    output["notes"].push_back(
        std::to_string(unresolvedForms) +
        " form action(s) could not be resolved and were not classified.");

  static const Args lures = {
      "verify your account", "confirm your account", "suspended account",
      "confirm your password", "update your payment", "unusual activity",
      "account will be closed", "account has been locked",
      "confirm your identity", "restore access to your account"};
  const bool urgency =
      visible.find("immediately") != S::npos ||
      visible.find("within 24 hours") != S::npos ||
      visible.find("limited time") != S::npos ||
      visible.find("expires today") != S::npos ||
      visible.find("act now") != S::npos;
  for (const auto &phrase : lures) {
    if (passwordForms && visible.find(phrase) != S::npos) {
      const bool externalUrgentCredentialRequest =
          externalPasswordForms > 0 && urgency;
      addFinding(
          findings, "credential_lure", "content",
          externalUrgentCredentialRequest ? "high" : "moderate",
          externalUrgentCredentialRequest
              ? "An urgent account prompt appears with a password form that "
                "submits credentials to a different registered domain."
              : "A credential form appears with an account-related prompt.",
          "Visible page text includes: \"" + phrase + "\"" +
              (externalUrgentCredentialRequest
                   ? "; urgent language and an external password destination "
                     "were also observed."
                   : "."),
          externalUrgentCredentialRequest ? 28 : 15,
          externalUrgentCredentialRequest ? 90 : 80,
          externalUrgentCredentialRequest ? "credential_pressure"
                                          : "credential_lure");
      break;
    }
  }
  const bool asksPayment =
      visible.find("credit card") != S::npos ||
      visible.find("bank account") != S::npos ||
      visible.find("payment details") != S::npos ||
      visible.find("payment information") != S::npos;
  if (urgency && asksPayment && sensitiveForms > 0)
    addFinding(findings, "urgent_sensitive_data_request", "content",
               "moderate",
               "Urgency language appears alongside a request for sensitive "
               "payment information.",
               "Urgency and payment-related language were both visible; "
               "sensitive form fields were present.",
               14, 70, "deceptive_pressure");
  if (html.size() >= MaxBodyBytes)
    output["notes"].push_back(
        "HTML inspection was limited to the configured response-size cap.");
  if (tagLimitReached)
    output["notes"].push_back(
        "HTML tag/form inspection stopped at its safety limit.");
  output["complete"] = !tagLimitReached;
  output["forms"] = forms.size();
  output["password_forms"] = passwordForms;
  output["external_forms"] = externalForms;
  output["sensitive_forms"] = sensitiveForms;
  output["external_links"] = externalLinks;
  output["external_resources"] = externalResources;
  output["meta_refresh"] = metaRefresh;
  output["link_evidence"] = linkEvidence;
  output["unresolved_forms"] = unresolvedForms;
  output["findings"] = findingsJson(findings);
  return output;
}

J inspectWebsite(const J &input) {
  return inspectWebsite(input, config::StrictlyDeniedDomains);
}

J inspectWebsite(const J &input, const std::set<S> &strictDenylist) {
  const S submitted = input.value("url", S());
  const S context = input.value("description", S());
  if (context.size() > 1500)
    throw Problem(400, "The website context exceeds the 1500-character limit.");
  ParsedUrl initial;
  S parseError;
  if (!parseUrl(submitted, initial, parseError))
    throw Problem(400, parseError);

  J checks = J::array({
      check("url", "URL validation and structure", "complete",
            "The submitted address was parsed locally."),
      check("dns", "DNS and domain inspection", "unavailable",
            "DNS inspection has not completed."),
      check("tls", "TLS and HTTPS inspection", "not_applicable",
            "TLS inspection will run only for HTTPS destinations."),
      check("http", "HTTP response inspection", "unavailable",
            "No HTTP response has been inspected."),
      check("redirect", "Redirect inspection", "unavailable",
            "No redirect response has been inspected."),
      check("content", "HTML and content inspection", "not_applicable",
            "Content inspection applies to HTML responses.")});
  std::vector<Finding> findings;
  J notes = J::array();
  const bool strictlyDenied =
      isStrictlyDeniedHost(initial.host, strictDenylist);
  if (strictlyDenied) {
    addFinding(findings, "strictly_denied_domain", "denylist", "high",
               "The hostname matches the local strict-deny list.",
               "Hostname: " + initial.host, 90, 100,
               "strict_domain_denylist");
    notes.push_back(
        "The hostname matches the local strict-deny list and receives at "
        "least 90 risk points.");
  }
  J tldPolicy;
  if (initial.isIp) {
    tldPolicy = {{"status", "not_applicable"},
                 {"tld", ""},
                 {"risk_points", 0},
                 {"explanation",
                  "The destination is an IP address with no DNS TLD; the TLD "
                  "rule was not applied."}};
  } else {
    const TldAssessment tld = assessTld(initial.host);
    if (tld.approved) {
      tldPolicy = {{"status", "approved"},
                   {"tld", tld.suffix},
                   {"risk_points", 0},
                   {"explanation",
                    "This TLD is on the approved list. No TLD-only penalty "
                    "was applied; this does not establish that the site is "
                    "safe."}};
    } else {
      const S evidence =
          "Hostname: " + initial.host + "; extracted TLD: " +
          (tld.suffix.empty() ? "(none)" : tld.suffix) +
          "; approved suffix list did not contain this TLD.";
      addFinding(findings, "unapproved_tld", "tld", "high",
                 "The hostname uses a TLD outside the approved TLD list.",
                 evidence, tld.riskPoints, 100, "approved_tld_policy");
      tldPolicy = {{"status", "unapproved"},
                   {"tld", tld.suffix},
                   {"risk_points", tld.riskPoints},
                   {"explanation",
                    "This TLD is not on the approved list; " +
                        std::to_string(tld.riskPoints) +
                        " risk points were applied. This alone does not prove "
                        "the website is malicious."}};
    }
  }
  J urlEvidence = J::array();
  const auto addUrlEvidence = [&](const S &id, const S &severity,
                                  const S &text, const S &evidence,
                                  int points, int reliability,
                                  const S &family) {
    addFinding(findings, id, "url", severity, text, evidence, points,
               reliability, family);
    urlEvidence.push_back(evidence);
  };

  if (initial.scheme == "http")
    addUrlEvidence("unencrypted_http", "low",
                   "The submitted address uses unencrypted HTTP.",
                   "Scheme: http", 8, 100, "transport");
  if (initial.isIp)
    addUrlEvidence("ip_literal", "moderate",
                   "The hostname is a numeric IP address rather than a "
                   "domain name.",
                   "Host: " + initial.host, 10, 95, "host_structure");
  if (initial.hasUserInfo)
    addUrlEvidence("userinfo", "high",
                   "User information in the URL can disguise its actual "
                   "destination.",
                   "Credentials were removed before any network request.",
                   20, 95, "destination_disguise");
  if (submitted.size() > 2048)
    addUrlEvidence("long_url", "low",
                   "The URL is unusually long and harder to review.",
                   "Submitted length: " + std::to_string(submitted.size()) +
                       " characters.",
                   submitted.size() > 4096 ? 7 : 4, 55, "url_complexity");
  const auto labels = static_cast<int>(
      std::count(initial.host.begin(), initial.host.end(), '.') + 1);
  if (labels >= 5)
    addUrlEvidence("deep_subdomains", "low",
                   "The hostname has an unusually deep subdomain structure.",
                   "Hostname contains " + std::to_string(labels) +
                       " labels.",
                   4, 60, "host_structure");
  if (initial.host.find("xn--") != S::npos)
    addUrlEvidence("punycode_hostname", "observation",
                   "The hostname contains an internationalized punycode "
                   "label; verify its spelling.",
                   "Punycode label present in the hostname.", 0, 100,
                   "host_structure");
  const auto encodedCount =
      static_cast<int>(std::count(initial.url.begin(), initial.url.end(), '%'));
  if (encodedCount >= 5)
    addUrlEvidence("encoded_url", "low",
                   "The URL contains many percent-encoded characters.",
                   std::to_string(encodedCount) +
                       " percent-encoded markers appear in the address.",
                   4, 50, "url_obfuscation");
  const auto queryStart = initial.url.find('?');
  if (queryStart != S::npos &&
      std::count(initial.url.begin() + static_cast<std::ptrdiff_t>(queryStart),
                 initial.url.end(), '&') >= 12)
    addUrlEvidence("complex_query", "low",
                   "The URL contains an unusually complex query string.",
                   "The query contains at least 12 parameters.", 3, 45,
                   "url_obfuscation");
  const S standardPort =
      initial.scheme == "https" ? "443" : "80";
  if (initial.port != standardPort)
    addUrlEvidence("nonstandard_port", "moderate",
                   "The address uses a nonstandard web port.",
                   "Port: " + initial.port, 5, 85, "port");

  const auto redirectQueryStart = initial.url.find('?');
  if (redirectQueryStart != S::npos) {
    const auto fragmentStart = initial.url.find('#', redirectQueryStart + 1);
    const size_t queryEnd = fragmentStart == S::npos ? initial.url.size()
                                                      : fragmentStart;
    size_t at = redirectQueryStart + 1;
    int inspectedParameters = 0;
    while (at < queryEnd && inspectedParameters++ < 64) {
      const auto end = initial.url.find('&', at);
      const size_t parameterEnd =
          end == S::npos || end > queryEnd ? queryEnd : end;
      const auto equals = initial.url.find('=', at);
      const size_t valueStart =
          equals == S::npos || equals >= parameterEnd ? parameterEnd
                                                       : equals + 1;
      const S key = lowerAscii(initial.url.substr(
          at, (equals == S::npos || equals >= parameterEnd ? parameterEnd
                                                            : equals) -
                  at));
      if (key == "next" || key == "url" || key == "target" ||
          key == "redirect" || key == "return" || key == "continue" ||
          key == "destination" || key == "dest") {
        const S value =
            decodePercent(initial.url.substr(valueStart,
                                             parameterEnd - valueStart));
        S absolute;
        ParsedUrl destination;
        S error;
        if (resolveReference(initial.url, value, absolute) &&
            parseUrl(absolute, destination, error) &&
            !sameSite(initial.host, destination.host)) {
          addFinding(
              findings, "external_navigation_parameter", "redirect", "low",
              "A navigation-related URL parameter contains a destination on "
              "a different registered domain; this does not prove a redirect "
              "will occur.",
              "Parameter: " + key + "; embedded destination hostname: " +
                  destination.host,
              5, 55, "redirect_parameter");
          break;
        }
      }
      at = parameterEnd + 1;
    }
  }

  const S registeredDomain = registrableDomain(initial.host);
  const S domainLabel = registrableLabel(initial.host);
  for (const auto &brand : knownBrands()) {
    if (hostIsBrandDomain(initial.host, brand))
      continue;
    bool characterSubstitution = false;
    const bool lookalike =
        brandLabelLooksLike(domainLabel, brand.root, characterSubstitution);
    const bool brandNameUsed =
        containsToken(registeredDomain, brand.root) ||
        containsToken(initial.host, brand.root);
    if (lookalike || brandNameUsed) {
      const S path = lowerAscii(initial.path);
      const bool brandAccountContext =
          path.find("login") != S::npos ||
          path.find("signin") != S::npos ||
          path.find("account") != S::npos ||
          path.find("verify") != S::npos ||
          containsToken(initial.host, "login") ||
          containsToken(initial.host, "signin") ||
          containsToken(initial.host, "account") ||
          containsToken(initial.host, "verify");
      const bool confirmedLookalikeImpersonation =
          lookalike && brandAccountContext;
      S brandEvidence = "Observed domain: " + registeredDomain +
                        "; brand reference: " + brand.name + " (" +
                        brand.root + ").";
      if (characterSubstitution)
        brandEvidence += " An ASCII character substitution resembles the "
                         "brand's domain label.";
      if (confirmedLookalikeImpersonation)
        brandEvidence +=
            " The lookalike is paired with login, account, or verification "
            "language in the hostname or path.";
      addFinding(findings,
                 lookalike ? "brand_lookalike_domain"
                           : "brand_name_in_unrelated_domain",
                 "identity",
                 confirmedLookalikeImpersonation ? "high" : "moderate",
                 confirmedLookalikeImpersonation
                     ? "A lookalike of a well-known brand is paired with a "
                       "login, account, or verification destination."
                     : "The registered hostname resembles or names a "
                       "well-known brand outside the local list of its "
                       "recognized domains.",
                 brandEvidence,
                 confirmedLookalikeImpersonation ? 60 : lookalike ? 20 : 15,
                 confirmedLookalikeImpersonation ? 90
                                                 : lookalike ? 72 : 65,
                 "brand_domain");
      if (brandAccountContext)
        addFinding(findings, "brand_account_path", "identity", "low",
                   "The brand-like hostname is paired with an account or "
                   "verification path.",
                   "Hostname: " + registeredDomain + "; path: " + initial.path,
                   8, 60, "brand_domain");
      break;
    }
  }

  setCheck(checks, "url",
           check("url", "URL validation and structure", "complete",
                 "The submitted URL was parsed using libcurl's URL parser.",
                 urlEvidence));
  notes.push_back(
      "URL structure checks identify indicators, not proof of malicious "
      "behavior.");
  for (const S &scheme : Args{"https://", "http://"}) {
    const auto at = lowerAscii(context).find(scheme);
    if (at == S::npos)
      continue;
    const auto end = context.find_first_of(" \t\r\n,;)", at);
    const S expectedUrl =
        context.substr(at, end == S::npos ? S::npos : end - at);
    ParsedUrl expected;
    S contextError;
    if (parseUrl(expectedUrl, expected, contextError) &&
        relatedHost(initial.host, expected.host) == "different") {
      notes.push_back(
          "The optional user-supplied context references " + expected.host +
          ", which differs from the submitted hostname " + initial.host +
          ". The context is not independently verified.");
      break;
    }
  }

  const auto deadline = Clock::now() + std::chrono::seconds(20);
  Resolution resolution = resolvePublic(initial, deadline);
  if (resolution.definitivelyMissing)
    addFinding(findings, "dns_hostname_unresolved", "dns", "low",
               "The DNS resolver reported no address records for this "
               "hostname. It may be misspelled or inactive; this alone does "
               "not establish fraud.",
               "Hostname: " + initial.host + "; resolver result: " +
                   resolution.message,
               8, 90, "hostname_resolution");
  const bool initialPortAllowed =
      (initial.scheme == "http" && initial.port == "80") ||
      (initial.scheme == "https" && initial.port == "443");
  J dnsEvidence = J::array();
  if (resolution.ok) {
    if (!resolution.ipv4.empty()) {
      S addresses = "A records: ";
      for (size_t i = 0; i < resolution.ipv4.size(); ++i) {
        if (i)
          addresses += ", ";
        addresses += resolution.ipv4[i];
      }
      dnsEvidence.push_back(addresses);
    }
    if (!resolution.ipv6.empty()) {
      S addresses = "AAAA records: ";
      for (size_t i = 0; i < resolution.ipv6.size(); ++i) {
        if (i)
          addresses += ", ";
        addresses += resolution.ipv6[i];
      }
      dnsEvidence.push_back(addresses);
    }
    if (!resolution.canonicalName.empty())
      dnsEvidence.push_back(
          "Resolver-reported canonical hostname: " +
          resolution.canonicalName);
    setCheck(checks, "dns",
             check("dns", "DNS and domain inspection", "complete",
                   "The operating-system resolver returned public address "
                   "records.",
                   dnsEvidence));
  } else {
    const S status = resolution.blocked ? "blocked" : "unavailable";
    dnsEvidence.push_back(resolution.message);
    setCheck(checks, "dns",
             check("dns", "DNS and domain inspection", status,
                   resolution.message, dnsEvidence));
  }

  J tlsEvidence = J::array();
  J httpEvidence = J::array();
  J redirectEvidence = J::array();
  J contentEvidence = J::array();
  bool tlsApplicable = initial.scheme == "https";
  bool tlsCompleted = false;
  bool httpReceived = false;
  bool redirectCompleted = false;
  bool redirectBlocked = false;
  bool contentApplicable = false;
  bool contentCompleted = false;
  bool responseTruncated = false;
  bool headersTruncated = false;
  bool responseIncomplete = false;
  bool redirectLimitReached = false;
  bool requestPolicyBlocked = false;
  bool terminalResponse = false;
  long finalStatus = 0;
  S finalContentType, finalHost = initial.host, finalUrl, finalBody, pageTitle;
  std::map<S, S> finalHeaders;
  J redirectRows = J::array();
  S failureMessage;

  if (resolution.ok && !initial.hasUserInfo && initialPortAllowed) {
    ParsedUrl current = initial;
    Resolution currentResolution = resolution;
    std::set<S> visited;
    visited.insert(current.url);
    for (int hop = 0; hop <= MaxRedirects; ++hop) {
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              deadline - Clock::now());
      if (remaining <= std::chrono::milliseconds::zero()) {
        failureMessage = "The total website inspection time limit was reached.";
        break;
      }
      const int timeoutMs = static_cast<int>(
          std::max<int64_t>(1, std::min<int64_t>(5000, remaining.count())));
      Transfer transfer;
      try {
        transfer = requestPage(current, currentResolution, timeoutMs);
      } catch (const std::exception &error) {
        failureMessage = error.what();
        break;
      }
      if (transfer.status > 0) {
        finalStatus = transfer.status;
        finalHeaders = transfer.headers;
        responseTruncated = transfer.truncated;
        headersTruncated = transfer.headersTruncated;
        responseIncomplete = transfer.transportIncomplete;
        httpReceived = true;
        finalHost = current.host;
        finalContentType = transfer.headers["content-type"];
        if (current.scheme == "https") {
          tlsApplicable = true;
          if (transfer.tlsVerifyResult == 0) {
            tlsCompleted = true;
            tlsEvidence.push_back("Certificate and hostname verification "
                                  "succeeded for " +
                                  current.host + ".");
            if (!transfer.certificateExpiry.empty())
              tlsEvidence.push_back("Certificate expiry: " +
                                    transfer.certificateExpiry);
          } else {
            tlsEvidence.push_back(
                "TLS certificate verification failed with code " +
                std::to_string(transfer.tlsVerifyResult) + ".");
          }
        }
      } else if (current.scheme == "https") {
        tlsApplicable = true;
        if (transfer.curlStatus == CURLE_PEER_FAILED_VERIFICATION) {
          tlsEvidence.push_back(curlFailure(transfer));
          if (!transfer.certificateExpiry.empty())
            tlsEvidence.push_back("Presented certificate expiry: " +
                                  transfer.certificateExpiry);
        } else {
          tlsEvidence.push_back("TLS connection could not be completed: " +
                                curlFailure(transfer));
        }
      }
      if (transfer.status <= 0) {
        failureMessage = curlFailure(transfer);
        break;
      }
      if (!redirectStatus(transfer.status)) {
        finalUrl = current.url;
        finalBody = std::move(transfer.body);
        redirectCompleted = true;
        terminalResponse =
            transfer.curlStatus == CURLE_OK || transfer.truncated;
        if (!terminalResponse)
          failureMessage = curlFailure(transfer);
        break;
      }
      const auto location = transfer.headers.find("location");
      if (location == transfer.headers.end() || location->second.empty()) {
        redirectEvidence.push_back(
            "The server returned a redirect without a usable Location header.");
        redirectCompleted = false;
        break;
      }
      S absolute;
      ParsedUrl next;
      S nextError;
      if (!resolveReference(current.url, location->second, absolute) ||
          !parseUrl(absolute, next, nextError)) {
        redirectEvidence.push_back(
            "A redirect destination was malformed and was not followed.");
        redirectBlocked = true;
        break;
      }
      if (next.scheme == "https")
        tlsApplicable = true;
      if (next.hasUserInfo) {
        redirectBlocked = true;
        redirectEvidence.push_back(
            "A redirect included URL user information and was not followed.");
        addFinding(findings, "redirect_userinfo", "redirect", "moderate",
                   "A redirect destination contains URL user information.",
                   "Credentials were not sent.", 18);
        break;
      }
      const bool nextPortAllowed =
          (next.scheme == "http" && next.port == "80") ||
          (next.scheme == "https" && next.port == "443");
      if (!nextPortAllowed) {
        redirectBlocked = true;
        redirectEvidence.push_back(
            "Redirect destination " + next.host +
            " uses a nonstandard port and was not contacted.");
        break;
      }
      if (hop == MaxRedirects) {
        redirectLimitReached = true;
        redirectEvidence.push_back(
            "The redirect chain exceeded the configured limit and was stopped.");
        addFinding(findings, "excessive_redirect_chain", "redirect",
                   "moderate", "The site returned an excessive redirect chain.",
                   std::to_string(redirectRows.size() + 1) +
                       " redirect responses were observed.",
                   10);
        break;
      }
      J row = {{"status", transfer.status},
               {"from_host", current.host},
               {"to_host", next.host},
               {"hostname_changed", current.host != next.host}};
      redirectRows.push_back(row);
      redirectEvidence.push_back(
          std::to_string(transfer.status) + " redirect: " + current.host +
          " → " + next.host + ".");
      if (current.host != next.host)
        notes.push_back("A redirect changed hostname from " + current.host +
                        " to " + next.host + ".");
      if (!sameSite(current.host, next.host))
        addFinding(findings, "cross_registered_domain_redirect", "redirect",
                   "low",
                   "A redirect changes the registered domain; this can be "
                   "legitimate but changes the destination identity.",
                   "Redirect changed from " + current.host + " (" +
                       registrableDomain(current.host) + ") to " + next.host +
                       " (" + registrableDomain(next.host) + ").",
                   6, 65, "redirect_destination");
      if (!visited.insert(next.url).second) {
        redirectLimitReached = true;
        redirectEvidence.push_back(
            "A redirect loop was detected and was not followed again.");
        addFinding(findings, "redirect_loop", "redirect", "moderate",
                   "The site returned a redirect loop.",
                   std::to_string(redirectRows.size()) +
                       " redirect responses were observed.",
                   8);
        break;
      }
      Resolution nextResolution = resolvePublic(next, deadline);
      if (!nextResolution.ok) {
        redirectBlocked = true;
        redirectEvidence.push_back(
            "Redirect destination " + next.host +
            " was not fetched: " + nextResolution.message);
        break;
      }
      for (const auto &address : nextResolution.addresses)
        redirectEvidence.push_back("Validated redirect address: " + address);
      current = std::move(next);
      currentResolution = std::move(nextResolution);
    }
  } else if (initial.hasUserInfo) {
    failureMessage =
        "The URL contained user information; credentials were removed and no "
        "network request was made.";
  } else if (resolution.ok && !initialPortAllowed) {
    requestPolicyBlocked = true;
    failureMessage =
        "Only HTTP on port 80 and HTTPS on port 443 are contacted.";
  } else if (!resolution.ok) {
    requestPolicyBlocked = resolution.blocked;
    failureMessage = resolution.message;
  }

  if (httpReceived) {
    httpEvidence.push_back(
        std::string(terminalResponse ? "Final" : "Last") +
        " HTTP status: " + std::to_string(finalStatus));
    httpEvidence.push_back("Responding hostname: " + finalHost);
    if (!finalContentType.empty())
      httpEvidence.push_back("Content-Type: " + finalContentType);
    for (const auto &header : finalHeaders)
      if (header.first != "location")
        httpEvidence.push_back(header.first + ": " + header.second);
    if (responseTruncated || responseIncomplete)
      httpEvidence.push_back(
          "Response body inspection was truncated or interrupted.");
    if (headersTruncated)
      httpEvidence.push_back(
          "Response headers exceeded the 32 KiB inspection limit.");
    setCheck(checks, "http",
             check("http", "HTTP response inspection",
                   responseTruncated || headersTruncated || responseIncomplete
                       ? "partial"
                       : "complete",
                   responseTruncated || headersTruncated || responseIncomplete
                       ? "The HTTP response was incomplete or reached an "
                         "inspection limit."
                       : "A bounded GET request returned an HTTP response.",
                   httpEvidence));
  } else {
    httpEvidence.push_back(failureMessage.empty()
                               ? "No HTTP response was received."
                               : failureMessage);
    setCheck(checks, "http",
             check("http", "HTTP response inspection",
                   requestPolicyBlocked || initial.hasUserInfo ? "blocked"
                                                               : "unavailable",
                   requestPolicyBlocked || initial.hasUserInfo
                       ? "The local scanner blocked this request under its "
                         "network-safety policy."
                       : "No HTTP response was received.",
                   httpEvidence));
  }

  if (tlsApplicable) {
    const S status = tlsCompleted ? "complete" : "unavailable";
    setCheck(checks, "tls",
             check("tls", "TLS and HTTPS inspection", status,
                   tlsCompleted
                       ? "HTTPS certificate and hostname verification "
                         "succeeded."
                       : "HTTPS certificate or connection verification could "
                         "not be completed.",
                   tlsEvidence));
  } else {
    setCheck(checks, "tls",
             check("tls", "TLS and HTTPS inspection", "not_applicable",
                   "No HTTPS connection was requested or reached.",
                   tlsEvidence));
  }

  if (redirectBlocked || requestPolicyBlocked || initial.hasUserInfo)
    setCheck(checks, "redirect",
             check("redirect", "Redirect inspection", "blocked",
                   requestPolicyBlocked || initial.hasUserInfo
                       ? "Redirect inspection was blocked because the initial "
                         "request did not pass the scanner policy."
                       : "An unsafe or malformed redirect destination was "
                         "not followed.",
                   redirectEvidence));
  else if (redirectCompleted)
    setCheck(checks, "redirect",
             check("redirect", "Redirect inspection", "complete",
                   "Redirect responses were checked manually; every followed "
                   "destination passed the network-address policy.",
                   redirectEvidence));
  else
    setCheck(checks, "redirect",
             check("redirect", "Redirect inspection", "unavailable",
                   redirectLimitReached
                       ? "The redirect chain could not be fully inspected."
                       : "Redirect behavior could not be determined.",
                   redirectEvidence));

  J contentInspection;
  if (terminalResponse && isHtmlType(finalContentType)) {
    contentApplicable = true;
    contentEvidence.push_back(
        "HTML is parsed as inert text; remote JavaScript is never executed.");
    contentInspection = inspectHtml(finalBody, finalUrl);
    pageTitle = contentInspection.value("title", S());
    if (!pageTitle.empty())
      contentEvidence.push_back("Page title: " + pageTitle);
    for (const auto &metadata : contentInspection["metadata"])
      contentEvidence.push_back(
          "Metadata " + metadata.value("name", S()) + ": " +
          metadata.value("content", S()));
    contentCompleted =
        !responseTruncated && !headersTruncated && !responseIncomplete &&
        contentInspection.value("complete", false);
    if (responseTruncated)
      contentEvidence.push_back(
          "The HTML body was truncated at the configured size limit.");
    for (const auto &finding : contentInspection["findings"]) {
      addFinding(findings, finding.value("id", S()),
                 finding.value("module", S()), finding.value("severity", S()),
                 finding.value("text", S()), finding.value("evidence", S()),
                 finding.value("points", 0),
                 finding.value("reliability", 80),
                 finding.value("family", S()));
    }
    for (const auto &note : contentInspection["notes"])
      notes.push_back(note);
    contentEvidence.push_back(
        "Forms found: " +
        std::to_string(contentInspection.value("forms", 0)) +
        "; password forms: " +
        std::to_string(contentInspection.value("password_forms", 0)) +
        "; forms with sensitive fields: " +
        std::to_string(contentInspection.value("sensitive_forms", 0)) +
        "; external forms: " +
        std::to_string(contentInspection.value("external_forms", 0)) +
        "; external links: " +
        std::to_string(contentInspection.value("external_links", 0)) +
        "; external resources: " +
        std::to_string(contentInspection.value("external_resources", 0)) +
        ".");
    for (const auto &link : contentInspection.value("link_evidence", J::array()))
      contentEvidence.push_back(link.get<S>());
    const S refresh = contentInspection.value("meta_refresh", S());
    if (!refresh.empty())
      contentEvidence.push_back(
          "A meta-refresh directive names hostname: " + refresh);
  } else if (terminalResponse) {
    setCheck(checks, "content",
             check("content", "HTML and content inspection", "not_applicable",
                   "The final response was not HTML.",
                   J::array({finalContentType.empty()
                                 ? "Content-Type was not provided."
                                 : "Content-Type: " + finalContentType})));
  } else {
    setCheck(checks, "content",
             check("content", "HTML and content inspection", "unavailable",
                   "No HTML response was available to inspect.",
                   J::array({failureMessage})));
  }

  if (contentApplicable) {
    setCheck(checks, "content",
             check("content", "HTML and content inspection",
                   contentCompleted ? "complete" : "partial",
                   contentCompleted
                       ? "HTML was inspected as inert text."
                       : "HTML inspection could not be completed.",
                   contentEvidence));
  }

  // A live response is required for a numeric score unless the local strict
  // denylist provides an authoritative policy verdict.
  const bool hasRemoteResponse = terminalResponse;
  const bool hasNumericVerdict = hasRemoteResponse || strictlyDenied;
  const ScoreResult scored = scoreFindings(findings);
  const int score = scored.score;
  int completed = 0, applicable = 0;
  for (const auto &item : checks) {
    const S status = item.value("status", S());
    if (status != "not_applicable") {
      ++applicable;
      completed += status == "complete" ? 1 : 0;
    }
  }
  const int confidence =
      applicable ? (100 * completed + applicable / 2) / applicable : 0;
  S category = "Unable to Verify";
  if (hasNumericVerdict) {
    category = categoryForScore(score);
  }
  S advice =
      category == "Highly Risky"
          ? "Do not enter credentials or payment details. Verify the destination "
            "through a separately obtained official address."
      : category == "Be Cautious"
          ? "Review the findings and independently verify the destination "
            "before sharing personal, login, or payment information."
      : category == "Safe"
          ? "No strong suspicious indicators were found in the checks completed. "
            "This is not a guarantee that the website is safe."
          : "The available evidence was insufficient to assess the website. "
            "Retry later or verify the destination through an official source.";

  J report = {{"type", "Website"},
              {"target", initial.host},
              {"hostname", initial.host},
              {"category", category},
              {"score", hasNumericVerdict ? J(score) : J(nullptr)},
              {"observed_score", score},
              {"tld_policy", tldPolicy},
              {"findings", findingsJson(findings)},
              {"notes", notes},
              {"advice", advice},
              {"source", "CyberShield local website inspection engine"},
              {"checks", checks},
              {"confidence",
               {{"completed", completed},
                {"applicable", applicable},
                {"planned", 6},
                {"percentage", confidence}}},
              {"scoring",
               {{"category_points", scored.categoryPoints},
                {"category_subtotal", scored.categorySubtotal},
                {"independent_categories", scored.independentCategories},
                {"corroboration_bonus", scored.corroborationBonus},
                {"total", hasNumericVerdict ? J(score) : J(nullptr)},
                {"observed_total", score},
                {"observed_scope",
                 hasRemoteResponse
                     ? "complete_inspection"
                     : strictlyDenied ? "strict_denylist"
                                      : "incomplete_inspection"},
                {"method",
                 "Finding points are reliability-weighted, correlated findings "
                 "within a family are capped, each category has a cap, and "
                 "independent categories with at least 10 points add a small "
                 "corroboration bonus. The final score is capped at 100; "
                 "missing checks add no risk. When full inspection does not "
                 "complete, observed_total is only a score of collected "
                 "evidence and is not a full-site verdict, except for an "
                 "explicit strict-denylist match."}}},
              {"indicator_coverage", indicatorCoverage()},
              {"redirects", redirectRows},
              {"inspection",
               {{"http_status", httpReceived ? J(finalStatus) : J(nullptr)},
                {"final_hostname", httpReceived ? J(finalHost) : J(nullptr)},
                {"content_type", finalContentType},
                {"page_title", pageTitle},
                {"page_metadata",
                 contentInspection.is_object()
                     ? contentInspection.value("metadata", J::array())
                     : J::array()},
                {"body_truncated", responseTruncated},
                {"response_incomplete", responseIncomplete}}}};
  if (!hasRemoteResponse && !failureMessage.empty())
    report["notes"].push_back(failureMessage);
  if (tlsCompleted)
    report["notes"].push_back(
        "A verified HTTPS certificate protects the connection but does not "
        "prove the site's identity or intent.");
  notes.push_back(
      "Scoring uses each finding's reliability-weighted points. Within a "
      "correlated evidence family, only the strongest signal and one quarter "
      "of the next strongest signal count. Category caps limit accumulation; "
      "independent categories with at least 10 points can add up to 12 "
      "corroboration points. The final score is capped at 100. Missing checks "
      "and technical failures add no risk.");
  notes.push_back(
      "Registered-domain comparisons use a small local list of common "
      "multi-label suffixes, not a complete Public Suffix List; those "
      "comparisons are approximate.");
  notes.push_back(
      "The brand/domain comparison list is limited and can be incomplete. "
      "Matching a listed domain does not verify ownership or legitimacy.");
  notes.push_back(
      "Domain age, registrar, nameservers, ownership, visual logos, and "
      "comprehensive Unicode lookalikes are not checked.");
  report["notes"].push_back(
      "No third-party verdict service was queried. The submitted site was "
      "fetched only by this local backend using bounded, read-only HTTP "
      "requests.");
  report["notes"].push_back(
      "No website is guaranteed safe by the absence of detected indicators.");
  report["score"] = hasNumericVerdict ? J(score) : J(nullptr);
  report["confidence"]["percentage"] = confidence;
  return report;
}
}
