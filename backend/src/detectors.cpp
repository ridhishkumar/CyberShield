#include "download_sources.h"
#include "dsa.h"
#include "download_source_registry.h"
#include "email_analyzer.h"
#include "sms_analyzer.h"
#include "sms_sender_registry.h"
#include "software_analyzer.h"
#include "website_inspector.h"
#include <asio/ip/address.hpp>
#include <regex>
#include <sstream>
using Findings = std::vector<Finding>;
static int softwareStrengthFromPoints(int points) {
  if (points >= 80)
    return 98;
  if (points >= 35)
    return 82;
  if (points >= 25)
    return 68;
  if (points >= 20)
    return 56;
  if (points >= 15)
    return 44;
  if (points >= 10)
    return 34;
  return points > 0 ? 24 : 0;
}
static void addSoftwareSignal(J &signals, const S &id, const S &name,
                              const S &category, const S &family, int strength,
                              int confidence, const S &explanation,
                              const S &evidence, const S &verification,
                              const S &method) {
  const S severity = strength >= 85   ? "Critical"
                     : strength >= 65 ? "High"
                     : strength >= 40 ? "Moderate"
                     : strength >= 20 ? "Low"
                                      : "Observation";
  signals.push_back({{"id", id},
                     {"name", name},
                     {"category", category},
                     {"family", family},
                     {"severity", severity},
                     {"score", std::max(0, std::min(100, strength))},
                     {"confidence", std::max(0, std::min(100, confidence))},
                     {"text", explanation},
                     {"evidence", evidence},
                     {"verification_status", verification},
                     {"detection_method", method}});
}
static S softwareUrlFamily(const S &text) {
  const S value = lower(text);
  if (value.find("redirect") != S::npos)
    return "redirect_parameter";
  if (value.find("user information") != S::npos ||
      value.find("percent-encoded") != S::npos ||
      value.find("encoded") != S::npos)
    return "destination_obfuscation";
  if (value.find("publisher domain") != S::npos ||
      value.find("lure phrase") != S::npos)
    return "brand_impersonation";
  if (value.find("unencrypted http") != S::npos)
    return "transport_security";
  if (value.find("numeric ip") != S::npos ||
      value.find("nonstandard port") != S::npos)
    return "host_anomaly";
  if (value.find("shortening service") != S::npos)
    return "hidden_destination";
  if (value.find("suffix") != S::npos)
    return "domain_context";
  return "url_structure";
}
static bool containsAny(const S &text, const Args &patterns) {
  for (auto &p : patterns)
    if (text.find(p) != S::npos)
      return true;
  return false;
}
static bool asksForSecret(const S &text) {
  const Args requests = {"send your password",
                         "enter your password",
                         "share your password",
                         "confirm your password",
                         "verify your password",
                         "enter your login credentials",
                         "send the code",
                         "send us the code",
                         "send your code",
                         "share your otp",
                         "share the code",
                         "provide your otp",
                         "send your otp",
                         "send us your otp",
                         "give me your otp",
                         "reply with your otp",
                         "reply with the code",
                         "reply with your verification code",
                         "send your verification code",
                         "send me the verification code",
                         "share your verification code"};
  for (const auto &request : requests) {
    for (size_t at = text.find(request); at != S::npos;
         at = text.find(request, at + request.size())) {
      const auto from = at > 20 ? at - 20 : 0;
      const S before = text.substr(from, at - from);
      bool warning = false;
      for (const S &prefix : Args{"never ", "do not ", "don't ", "not to "})
        if (before.size() >= prefix.size() &&
            before.compare(before.size() - prefix.size(), prefix.size(),
                           prefix) == 0)
          warning = true;
      if (!warning)
        return true;
    }
  }
  return false;
}
static S wordsOnly(const S &s) {
  S out;
  for (unsigned char c : lower(s)) {
    if (c >= 128 || std::isalnum(c))
      out += static_cast<char>(c);
    else if (!out.empty() && out.back() != ' ')
      out += ' ';
  }
  while (!out.empty() && out.back() == ' ')
    out.pop_back();
  return out;
}
static S productNameKey(const S &name) {
  S value = lower(name);
  static const std::regex plusPlus(R"(\+\+)");
  static const std::regex extension(R"(\.(exe|msi|dmg|appimage)$)");
  static const std::regex architecture(
      R"(\s*\((x64|x86|arm64|64[- ]bit|32[- ]bit)\)$)");
  static const std::regex qualifier(
      R"(\s+(x64|x86|arm64|64[- ]bit|32[- ]bit|installer|setup|download|for windows|for macos|for linux)$)");
  static const std::regex version(R"(\s+v?[0-9]+(\.[0-9]+){0,3}$)");
  value = std::regex_replace(value, plusPlus, " plus plus");
  value = std::regex_replace(value, extension, "");
  value = std::regex_replace(value, architecture, "");
  std::smatch suffix;
  while (true) {
    if (std::regex_search(value, suffix, qualifier))
      value.erase(static_cast<size_t>(suffix.position()));
    else if (std::regex_search(value, suffix, version))
      value.erase(static_cast<size_t>(suffix.position()));
    else
      break;
  }
  return wordsOnly(value);
}
static bool matchesProductName(const Product &product, const S &name) {
  for (const auto &alias : product.names)
    if (productNameKey(alias) == name)
      return true;
  return false;
}
static S publisherKey(const S &publisher) {
  S value = wordsOnly(publisher);
  static const Args legalSuffixes = {
      "incorporated", "inc", "corporation", "corp", "limited", "ltd",
      "llc", "plc"};
  bool removed = true;
  while (removed) {
    removed = false;
    for (const auto &suffix : legalSuffixes) {
      const S ending = " " + suffix;
      if (value.size() >= ending.size() &&
          value.compare(value.size() - ending.size(), ending.size(), ending) ==
              0) {
        value.erase(value.size() - ending.size());
        removed = true;
        break;
      }
    }
  }
  return value;
}
static bool unknownPublisherClaim(const S &publisher) {
  const S value = publisherKey(publisher);
  return value.empty() ||
         value == "unknown" ||
         value == "unknown publisher" ||
         value == "not provided" ||
         value == "not known" ||
         value == "publisher unknown" ||
         value == "unverified" ||
         value == "unverifiable";
}
static bool hasPhrase(const S &normalized, const S &phrase) {
  return (" " + normalized + " ").find(" " + phrase + " ") != S::npos;
}
static bool sharedHost(const S &host) {
  return linearSearch({"github.com", "sourceforge.net", "apps.microsoft.com",
                       "store.steampowered.com", "play.google.com",
                       "apps.apple.com"},
                      host);
}
static bool hostMatchesDomain(const S &host, const S &domain) {
  return host == domain ||
         (!sharedHost(domain) && host.size() > domain.size() &&
          host.compare(host.size() - domain.size(), domain.size(), domain) ==
              0 &&
          host[host.size() - domain.size() - 1] == '.');
}
static bool knownOfficialSourceDomain(const S &host) {
  for (const auto &source : downloadSourceRegistry()) {
    if (!sharedHost(source.host) &&
        hostMatchesDomain(host, source.host))
      return true;
    for (const auto &alias : source.aliases)
      if (!sharedHost(alias.host) && hostMatchesDomain(host, alias.host))
        return true;
  }
  return false;
}
static bool pathMatch(const S &path, const S &prefix) {
  // An encoded or relative path may be interpreted differently by the server.
  if (path.find('%') != S::npos || path.find("/./") != S::npos ||
      (path + "/").find("/../") != S::npos)
    return false;
  return prefix == "/" ? path == "/"
                       : path == prefix || path.rfind(prefix + "/", 0) == 0;
}
static S website(S url, Findings &f, S *outPath = nullptr) {
  const auto first = url.find_first_not_of(" \t\r\n");
  if (first == S::npos)
    throw Problem(400, "Enter a website address.");
  url = url.substr(first, url.find_last_not_of(" \t\r\n") - first + 1);
  if (url.size() > 2048 || url.find_first_of(" \t\r\n\\") != S::npos)
    throw Problem(400, "Remove spaces or backslashes from the address.");
  if (url.rfind("//", 0) == 0)
    url = "https:" + url;
  auto split = url.find("://");
  if (split != S::npos && url.find_first_of("/?#") < split)
    split = S::npos;
  if (split == S::npos) {
    const S authority = url.substr(0, url.find_first_of("/?#"));
    if (authority.empty() || authority.find('@') != S::npos ||
        (lower(authority) != "localhost" &&
         lower(authority).rfind("localhost:", 0) != 0 &&
         authority.find('.') == S::npos && authority.front() != '['))
      throw Problem(
          400,
          "Enter a domain such as example.in or a complete HTTP(S) address.");
    url = "https://" + url;
    split = 5;
  }
  S scheme = lower(url.substr(0, split));
  if (split == S::npos || (scheme != "http" && scheme != "https"))
    throw Problem(400, "Include http:// or https:// in the URL.");
  auto end = url.find_first_of("/?#", split + 3);
  S host = lower(url.substr(split + 3, end - (split + 3)));
  auto at = host.rfind('@');
  if (at != S::npos) {
    f.push_back(
        {"User information before the hostname can disguise the destination.",
         35});
    host.erase(0, at + 1);
  }
  if (host.find('%') != S::npos) {
    f.push_back({"The raw hostname contains percent-encoded characters that "
                 "can hide its destination.",
                 25});
    S decoded;
    for (size_t i = 0; i < host.size(); ++i) {
      if (host[i] != '%') {
        decoded += host[i];
        continue;
      }
      if (i + 2 >= host.size() ||
          !std::isxdigit(static_cast<unsigned char>(host[i + 1])) ||
          !std::isxdigit(static_cast<unsigned char>(host[i + 2])))
        throw Problem(400, "The hostname contains invalid percent encoding.");
      const auto digit = [](char c) {
        return c <= '9' ? c - '0'
                        : lower(S(1, c))[0] - 'a' + 10;
      };
      decoded += static_cast<char>(digit(host[i + 1]) * 16 +
                                   digit(host[i + 2]));
      i += 2;
    }
    host = lower(decoded);
  }
  S port;
  auto colon = host.rfind(':');
  if (colon != S::npos &&
      (host.empty() || host[0] != '[' || colon > host.find(']'))) {
    port = host.substr(colon + 1);
    host.resize(colon);
    if (!std::regex_match(port, std::regex("[0-9]{1,5}")) ||
        std::stoi(port) > 65535)
      throw Problem(400, "Invalid port.");
  }
  if (host.size() > 253 || host.empty())
    throw Problem(400, "Invalid hostname.");
  if (host.back() == '.')
    host.pop_back();
  bool brackets = host.size() > 2 && host.front() == '[' && host.back() == ']';
  if (brackets)
    host = host.substr(1, host.size() - 2);
  asio::error_code ec;
  auto ip = asio::ip::make_address(host, ec);
  if (!ec) {
    if (ip.is_v6() != brackets)
      throw Problem(400, "Check IPv6 address brackets.");
    f.push_back(
        {"The address uses a numeric IP instead of a domain name.", 20});
  } else {
    if (host.find_first_not_of("0123456789.") == S::npos)
      throw Problem(400, "Invalid numeric IP address.");
    if (brackets || host.empty() || host.back() == '.')
      throw Problem(400, "Invalid hostname.");
    std::stringstream parts(host);
    S label;
    while (std::getline(parts, label, '.'))
      if (!std::regex_match(label,
                            std::regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")))
        throw Problem(
            400,
            "Use a valid hostname, with international domains in punycode.");
  }
  if (scheme == "http")
    f.push_back({"The submitted link uses unencrypted HTTP.", 15});
  const size_t queryStart = url.find('?');
  const size_t destinationLength =
      queryStart == S::npos ? url.size() : queryStart;
  if (destinationLength > 150)
    f.push_back({"The long URL makes the destination harder to inspect.", 10});
  if (std::count(host.begin(), host.end(), '.') >= 4)
    f.push_back({"Several subdomains precede the registered domain.", 15});
  if (host.find("xn--") != S::npos)
    f.push_back(
        {"An encoded international domain warrants a spelling check.", 10});
  S path = end == S::npos || url[end] != '/'
               ? "/"
               : url.substr(end, url.find_first_of("?#", end) - end);
  if (outPath)
    *outPath = path;
  const S hostWords = wordsOnly(host), pathWords = wordsOnly(path);
  // Additional structural signals. These are indicators, not proof of fraud.
  static const Args shorteners = {
      "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly",
      "rb.gy", "shorturl.at", "rebrand.ly", "ow.ly", "buff.ly"};
  if (linearSearch(shorteners, host))
    f.push_back({"The address uses a URL-shortening service, which hides the final destination.", 20});
  static const Args riskySuffixes = {
      ".zip", ".mov", ".click", ".top", ".work", ".support",
      ".rest", ".country", ".gq", ".tk", ".ml", ".cf",
      ".xyz", ".online", ".site", ".live"};
  for (const auto &suffix : riskySuffixes) {
    if (host.size() > suffix.size() &&
        host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) {
      f.push_back({"The domain uses a suffix frequently seen in low-cost or abuse-prone registrations; this alone does not make it malicious.", 8});
      break;
    }
  }
  const auto labels = static_cast<int>(std::count(host.begin(), host.end(), '.')) + 1;
  if (labels >= 5)
    f.push_back({"The hostname has an unusually deep subdomain structure.", 12});
  if (containsAny(pathWords, {"login", "signin", "verify", "account", "password", "payment", "wallet"}) &&
      (host.find('-') != S::npos || labels >= 4))
    f.push_back({"A sensitive account-related path is combined with a complex hostname.", 12});
  for (const S &phrase :
       Args{"verify account", "secure login", "free prize", "claim reward",
            "unlock account", "wallet recovery", "verify password",
            "cracked download"}) {
    if (hasPhrase(hostWords, phrase) || hasPhrase(pathWords, phrase)) {
      f.push_back(
          {"The address contains the lure phrase “" + phrase + "”.", 30});
      break;
    }
  }
  bool imitatedHost = false;
  for (const auto &source : downloadSourceRegistry()) {
    if (source.host == host)
      continue;
    const bool endsWithOfficial =
        host.size() > source.host.size() &&
        host.compare(host.size() - source.host.size(), source.host.size(),
                     source.host) == 0 &&
        host[host.size() - source.host.size() - 1] == '.';
    if (host.find(source.host) != S::npos && !endsWithOfficial)
      imitatedHost = true;
  }
  if (imitatedHost)
    f.push_back({"A publisher domain appears inside a different hostname. Read "
                 "the destination from right to left.",
                 35});
  if (!port.empty() && port != (scheme == "https" ? "443" : "80"))
    f.push_back({"The URL uses a nonstandard port; check that this is the "
                 "intended service.",
                 10});
  const S addressText = lower(url);
  if (containsAny(addressText,
                  {"url=https://", "url=http://", "url=https%3a", "url=http%3a",
                   "redirect=https%3a", "redirect=http%3a", "redirect=https://",
                   "redirect=http://", "redirect_uri=https%3a", "next=https://",
                   "next=http://"}))
    f.push_back({"A redirect parameter contains another destination. Inspect "
                 "the destination before following it.",
                 25});
  if (linearSearch({"phishing.example", "malware.example"}, host))
    f.push_back(
        {"Matches the project's reserved demonstration domain list.", 80});
  return host;
}
static const DownloadSourceEntry *listedDownloadSource(const S &host,
                                                       const S &path,
                                                       bool hostnameOnly) {
  for (const auto &source : downloadSourceRegistry()) {
    if (host == source.host &&
        (hostnameOnly || pathMatch(path, source.path)))
      return &source;
    for (const auto &alias : source.aliases)
      if (host == alias.host &&
          (hostnameOnly || pathMatch(path, alias.path)))
        return &source;
  }
  for (const auto &source : downloadSourceRegistry()) {
    if (hostMatchesDomain(host, source.host) &&
        (hostnameOnly || pathMatch(path, source.path)))
      return &source;
    for (const auto &alias : source.aliases)
      if (hostMatchesDomain(host, alias.host) &&
          (hostnameOnly || pathMatch(path, alias.path)))
        return &source;
  }
  return nullptr;
}
static S normalizeSmsMessage(const S &message) {
  S out;
  for (size_t i = 0; i < message.size();) {
    const auto starts = [&](const char *bytes, size_t length) {
      return message.compare(i, length, bytes, length) == 0;
    };
    if (starts("\xE2\x80\x8B", 3) || starts("\xE2\x80\x8C", 3) ||
        starts("\xE2\x80\x8D", 3) || starts("\xEF\xBB\xBF", 3) ||
        starts("\xE2\x80\x8E", 3) || starts("\xE2\x80\x8F", 3)) {
      i += 3;
      continue;
    }
    if (starts("\xC2\xA0", 2) || starts("\xE2\x80\xAF", 3)) {
      if (!out.empty() && out.back() != ' ')
        out += ' ';
      i += starts("\xC2\xA0", 2) ? 2 : 3;
      continue;
    }
    const unsigned char c = static_cast<unsigned char>(message[i++]);
    if (c < 0x20 || c == 0x7f) {
      if (!out.empty() && out.back() != ' ')
        out += ' ';
    } else {
      out += static_cast<char>(c);
    }
  }
  return lower(out);
}
static S normalizedSender(const S &sender) {
  S value;
  for (unsigned char c : lower(sender))
    if (std::isalnum(c))
      value += static_cast<char>(c);
  return value;
}
static const SmsOrganization *knownSmsSender(const S &sender) {
  const S normalized = normalizedSender(sender);
  if (normalized.empty())
    return nullptr;
  for (const auto &organization : smsOrganizationRegistry()) {
    for (const auto &id : organization.senderIds)
      if (normalized == normalizedSender(id))
        return &organization;
    for (const auto &number : organization.phoneNumbers)
      if (normalized == normalizedSender(number))
        return &organization;
  }
  return nullptr;
}
static const SmsOrganization *claimedSmsOrganization(const S &text) {
  const S normalized = wordsOnly(text);
  for (const SmsOrganization &organization : smsOrganizationRegistry()) {
    if (hasPhrase(normalized, wordsOnly(organization.name)))
      return &organization;
    for (const S &alias : organization.aliases)
      if (hasPhrase(normalized, wordsOnly(alias)))
        return &organization;
  }
  return nullptr;
}
static bool officialSmsDomain(const S &host,
                              const SmsOrganization &organization) {
  for (const auto &domain : organization.officialDomains)
    if (host == domain ||
        (host.size() > domain.size() &&
         host.compare(host.size() - domain.size(), domain.size(), domain) ==
             0 &&
         host[host.size() - domain.size() - 1] == '.'))
      return true;
  return false;
}
static S mailbox(S raw) {
  auto start = raw.rfind('<'), end = raw.find('>', start);
  if (start != S::npos && end != S::npos)
    raw = raw.substr(start + 1, end - start - 1);
  auto first = raw.find_first_not_of(" \r\t\n");
  if (first != S::npos)
    raw = raw.substr(first, raw.find_last_not_of(" \r\t\n") - first + 1);
  if (!std::regex_match(raw, std::regex(R"([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)")))
    throw Problem(400, "Enter a valid sender email address.");
  return lower(raw);
}
static bool consumerMailboxAddress(const S &address) {
  const auto separator = address.rfind('@');
  if (separator == S::npos)
    return false;
  const S domain = lower(address.substr(separator + 1));
  static const Args consumerDomains = {
      "gmail.com",      "googlemail.com", "outlook.com", "hotmail.com",
      "live.com",       "yahoo.com",      "yahoo.co.in", "icloud.com",
      "me.com",         "aol.com",        "proton.me",   "protonmail.com"};
  return linearSearch(consumerDomains, domain);
}
J softwareSources() {
  J entries = J::array();
  for (const auto &source : downloadSourceRegistry()) {
    entries.push_back({{"product", source.source},
                       {"url", source.reference}});
  }
  return entries;
}
J analyze(const S &type, const J &j) {
  if (type == "Website")
    return website_inspector::inspectWebsite(j);
  if (type == "Email")
    return analyzeEmail(j);
  if (type == "SMS")
    return analyzeSms(j);
  Findings f;
  S target, source = "Local, transparent rules",
            advice = "Verify the destination through an independently obtained "
                     "official address.";
  J notes = J::array();
  S hostname;
  bool knownSource = false;
  bool recognizedSource = false;
  const DownloadSourceEntry *matchedSource = nullptr;
  int confidencePenalty = 0;
  S path, basis;
  J softwareSignals = J::array();
  J softwareContext = J::object();
  S submittedSoftwareUrl;
  S declaredPublisher;
  bool sourceUsesHttp = false;
  Findings validationFindings;
  if (type == "Website" || type == "Software") {
    const bool software = type == "Software";
    S submitted = field(j, "url", 2048, !software);
    S app, publisher;
    if (software) {
      app = field(j, "name", 120, false);
      publisher = field(j, "publisher", 120, false);
      declaredPublisher = publisher;
      if (app.find_first_not_of(" \t\n\r") == S::npos && submitted.empty())
        throw Problem(400, "Enter the software name or its download address.");
    }
    if (!submitted.empty()) {
      if (software)
        submittedSoftwareUrl = submitted;
      Findings &urlFindings = software ? f : validationFindings;
      const size_t firstUrlFinding = urlFindings.size();
      hostname = website(submitted, urlFindings, &path);
      if (software) {
        for (size_t i = firstUrlFinding; i < urlFindings.size(); ++i) {
          const Finding &finding = urlFindings[i];
          const bool redirect =
              lower(finding.text).find("redirect") != S::npos;
          addSoftwareSignal(
              softwareSignals, redirect ? "redirect_parameter"
                                         : "url_structure_warning",
              redirect ? "Nested redirect destination"
                       : "URL structure warning",
              redirect ? "redirect_destination" : "source_domain",
              softwareUrlFamily(finding.text),
              softwareStrengthFromPoints(finding.points), 82, finding.text,
              hostname, "heuristic", "URL structure parser");
        }
      }
      target = hostname;
      const auto first = submitted.find_first_not_of(" \t\r\n");
      const S trimmed =
          first == S::npos
              ? S()
              : submitted.substr(first, submitted.find_last_not_of(" \t\r\n") -
                                            first + 1);
      const bool hostnameOnly =
          trimmed.find("://") == S::npos &&
          trimmed.rfind("//", 0) != 0 &&
          trimmed.find_first_of("/?#") == S::npos;
      if (software) {
        matchedSource = listedDownloadSource(hostname, path, hostnameOnly);
        recognizedSource = matchedSource != nullptr;
      }
      const S address = lower(submitted);
      sourceUsesHttp =
          address.find("http://") == address.find_first_not_of(" \t\n\r");
      notes.push_back("Source host: " + hostname);
      notes.push_back(sourceUsesHttp ? "The address uses HTTP."
                                     : "The address uses or defaults to HTTPS.");
      S context = lower(field(j, "description", 1500, false));
      std::smatch expected;
      if (std::regex_search(context, expected,
                            std::regex(R"(https?://([a-z0-9.-]+))")) &&
          expected[1].str() != hostname)
        notes.push_back("The context mentions a different host. Confirm the "
                        "intended service.");
    }
    const S productName = productNameKey(app);
    const Product *match = nullptr;
    if (software)
      for (const auto &product : downloadCatalogue()) {
        if (!matchesProductName(product, productName))
          continue;
        match = &product;
        for (const auto &ref : product.sources) {
          if (!path.empty() && hostMatchesDomain(hostname, ref.host) &&
              pathMatch(path, ref.path) &&
              (!sharedHost(ref.host) || hostname != "github.com" ||
               path == ref.path ||
               path == ref.path + "/" ||
               pathMatch(path, ref.path + "/releases")))
            knownSource = true;
        }
      }
    bool productBrandedHost = false;
    if (match && !hostname.empty()) {
      const S hostTerms = wordsOnly(hostname);
      for (const auto &alias : match->names) {
        const S aliasKey = productNameKey(alias);
        if (aliasKey.size() >= 4 && hasPhrase(hostTerms, aliasKey)) {
          productBrandedHost = true;
          break;
        }
      }
      if (!productBrandedHost)
        for (const auto &publisherName : match->publishers) {
          const S publisherTerms = publisherKey(publisherName);
          if (!publisherTerms.empty() &&
              hasPhrase(hostTerms, publisherTerms)) {
            productBrandedHost = true;
            break;
          }
        }
    }
    if (software) {
      target = app.empty() ? hostname : app;
      if (!publisher.empty())
        notes.push_back("Declared publisher: " + publisher);
      if (containsAny(wordsOnly(app + " " + submitted),
                      {"keygen", "cracked", "crack installer"})) {
        f.push_back(
            {"The name or download address suggests unofficial distribution.",
             0});
        addSoftwareSignal(
            softwareSignals, "unofficial_distribution", "Unofficial distribution wording",
            "publisher_consistency", "unofficial_distribution", 55, 74,
            "The supplied software name or address includes wording associated "
            "with unofficial distribution.",
            app, "heuristic", "Product and URL text");
      }
      if (match) {
        const bool knownLegitimateDomain =
            knownOfficialSourceDomain(hostname);
        const bool hasBrandImpersonationSignal =
            std::any_of(softwareSignals.begin(), softwareSignals.end(),
                        [](const J &signal) {
                          return signal.is_object() &&
                                 signal.value("family", S()) ==
                                     "brand_impersonation";
                        });
        const bool knownDifferentProductSource =
            matchedSource && matchedSource->source != match->label;
        if (!hostname.empty() && !knownSource &&
            ((productBrandedHost && !knownLegitimateDomain) ||
             knownDifferentProductSource)) {
          const bool brandLookalike =
              productBrandedHost && !knownLegitimateDomain;
          addSoftwareSignal(
              softwareSignals, "product_source_mismatch",
              brandLookalike ? "Product-branded unlisted hostname"
                             : "Download location belongs to another listed source",
              "publisher_consistency", "product_source_mismatch",
              brandLookalike ? 50 : 56, 83,
              brandLookalike
                  ? "The hostname contains the product name but is not a "
                    "configured publisher domain. This is a risk indicator, "
                    "not proof of malicious activity."
                  : "The supplied download location matches a configured "
                    "source for a different product.",
              hostname, "configured_reference_comparison",
              "Local product registry");
          if (hasBrandImpersonationSignal)
            softwareSignals.erase(
                std::remove_if(softwareSignals.begin(), softwareSignals.end(),
                               [](const J &signal) {
                                 return signal.is_object() &&
                                        signal.value("id", S()) ==
                                            "product_source_mismatch";
                               }),
                softwareSignals.end());
        }
        if (!publisher.empty() &&
            !unknownPublisherClaim(publisher) &&
            std::none_of(match->publishers.begin(), match->publishers.end(),
                         [&](const S &knownPublisher) {
                           return publisherKey(knownPublisher) ==
                                  publisherKey(publisher);
                         })) {
          f.push_back({"The declared publisher differs from the publisher "
                       "listed for this product.",
                       0});
          addSoftwareSignal(
              softwareSignals, "declared_publisher_mismatch",
              "Declared publisher differs from product reference",
              "publisher_consistency", "declared_publisher_mismatch", 100, 96,
              "The declared publisher does not match the configured publisher "
              "reference for this product. A user-entered name alone does "
              "not verify the source or file.",
              publisher + " vs " + match->label,
              "configured_reference_comparison",
              "Local product registry");
        }
        if (!publisher.empty() && unknownPublisherClaim(publisher)) {
          addSoftwareSignal(
              softwareSignals, "publisher_identity_uncertain",
              "Publisher identity is unknown or unverified",
              "publisher_consistency", "publisher_uncertainty", 50, 82,
              "The declared publisher does not establish a verifiable "
              "publisher identity for this software.",
              publisher, "uncertainty_not_mismatch",
              "Local product registry");
        }
      }
      const bool productSourceMismatch =
          std::any_of(softwareSignals.begin(), softwareSignals.end(),
                      [](const J &signal) {
                        return signal.is_object() &&
                               signal.value("id", S()) ==
                                   "product_source_mismatch";
                      });
      const bool suspiciousUrlEvidence =
          std::any_of(softwareSignals.begin(), softwareSignals.end(),
                      [](const J &signal) {
                        if (!signal.is_object())
                          return false;
                        const S family = signal.value("family", S());
                        return family == "brand_impersonation" ||
                               family == "destination_obfuscation" ||
                               family == "redirect_parameter" ||
                               family == "host_anomaly" ||
                               family == "hidden_destination" ||
                               family == "domain_context";
                      });
      const bool sourceVerified =
          (recognizedSource || knownSource ||
           (knownOfficialSourceDomain(hostname) &&
            (path.empty() || path == "/") &&
            match &&
            (match->label == "7-Zip" ||
             match->label == "VLC media player" ||
             match->label == "Mozilla Firefox"))) &&
          !sourceUsesHttp &&
          !productSourceMismatch && !suspiciousUrlEvidence;
      const S sourceStatus =
          productSourceMismatch || suspiciousUrlEvidence
              ? "SUSPICIOUS"
              : sourceVerified ? "VERIFIED_OFFICIAL" : "UNVERIFIED";
      if (sourceStatus == "UNVERIFIED" && !hostname.empty()) {
        addSoftwareSignal(
            softwareSignals, "unverified_download_source",
            "Unverified download source",
            "source_domain", "unverified_source", 85, 92,
            "No configured official-source reference established this download "
            "source as authentic. This is uncertainty, not a claim that the "
            "software is confirmed malicious.",
            hostname, "local_source_registry",
            "Local official-domain and download-source registry");
      }
      softwareContext["source_status"] = sourceStatus;
      if (sourceStatus == "VERIFIED_OFFICIAL" && matchedSource)
        notes.push_back("Configured official-source reference matched: " +
                        matchedSource->source + ".");
      else if (sourceStatus == "VERIFIED_OFFICIAL" && knownSource)
        notes.push_back(
            "The hostname and path match a configured product download "
            "reference.");
      if (app.empty())
        basis = "The download address was checked. Add the application name to "
                "compare it with its publisher.";
      else if (sourceStatus == "VERIFIED_OFFICIAL")
        basis = "The hostname and download path match a configured official "
                "source reference. This does not verify the file or every "
                "link on that site.";
      else if (knownOfficialSourceDomain(hostname))
        basis = "The hostname matches a configured publisher domain, but this "
                "path does not match a configured download reference.";
      else if (!match)
        basis = "There is no matching product in the local catalogue. Its "
                "publisher and download source are unverified.";
      else if (hostname.empty())
        basis = "A product name matched. Add its download URL to check the "
                "distribution source.";
      else
        basis = "The supplied details do not establish an official download "
                "location for this product.";
      if (sharedHost(hostname))
        notes.push_back("This platform hosts multiple products. Check the "
                        "specific publisher and listing.");
      advice = "Use a publisher download page and check the installer's "
               "digital signature before opening it.";
      if (sourceStatus == "SUSPICIOUS")
        advice =
            "Do not download from this address. CyberShield found source or "
            "identity inconsistencies; verify the publisher and address "
            "independently before taking action.";
      else if (sourceStatus == "UNVERIFIED")
        advice =
            submitted.empty()
                ? "No download address was supplied. CyberShield cannot "
                  "recommend a source; verify it through a channel you "
                  "already trust."
                : "Do not download from this address unless you independently "
                  "verify it through a source you already trust. CyberShield "
                  "could not establish it as official.";
      else
        advice =
            "This address matches a configured official-source reference. "
            "That does not verify a downloaded file; check its digital "
            "signature before opening it.";
    }
    if (software) {
      // A missing publisher match is an evidence gap, not proof of a scam.
      confidencePenalty += recognizedSource ? 15 : 30;
      if (hostname.empty() && !knownSource)
        f.push_back(
            {"Source verification allowance: the product and source could "
             "not be confirmed together.",
             0});
    }
    if (software) {
      softwareContext = {
          {"product", match ? match->label : S()},
          {"known_publishers", match ? J(match->publishers) : J::array()},
          {"declared_publisher", publisher},
          {"source_status", softwareContext.value("source_status", S())}};
    }
    if (type == "Software")
      notes.push_back(
          "The report shows a risk score, not a trust score. A recognized "
          "source does not verify the downloaded file or every link on that "
          "site. CyberShield analyzes pasted addresses without opening them.");
    else
      notes.push_back(
          "The risk score is the sum of detected indicators (capped at 100). "
          "Missing evidence is reported separately and does not by itself "
          "prove malicious activity.");
    notes.push_back(
        "Assessment uses URL structure and bundled official-source and "
        "publisher references. "
        "The checker does not open or execute the website.");
  } else {
    const bool sms = type == "SMS";
    S body = field(j, "content", sms ? 5000 : 20000);
    S sender, subject, headers;
    if (sms) {
      sender = field(j, "sender", 128, false);
      if (sender.empty())
        sender = field(j, "phone", 32, false);
    } else {
      sender = field(j, "sender", 254, false);
      subject = field(j, "subject", 300, false);
      headers = field(j, "headers", 8192, false);
      if (!sender.empty())
        sender = mailbox(sender);
    }
    S text = sms ? normalizeSmsMessage(body)
                 : lower(body + " " + subject);
    target = sms ? "SMS message" : "Email analysis";
    advice = "Confirm unexpected requests independently using the "
             "organisation's official app or a trusted contact number.";
    const S words = wordsOnly(text);
    const SmsOrganization *claimedOrganization =
        claimedSmsOrganization(text);
    const SmsOrganization *senderOrganization =
        sms ? knownSmsSender(sender) : nullptr;
    if (claimedOrganization) {
      notes.push_back("The message claims to be from " +
                      claimedOrganization->name + ".");
      notes.push_back("Configured official-domain reference: " +
                      claimedOrganization->reference + ".");
    }
    if (sms && !sender.empty()) {
      if (!senderOrganization) {
        f.push_back({"The supplied sender is unverified; it does not match a "
                     "verified sender value in the local registry.",
                     5});
        notes.push_back("Sender verification: unverified. A brand name in a "
                        "sender value does not establish ownership.");
      } else {
        notes.push_back("Sender matches a configured sender value for " +
                        senderOrganization->name +
                        "; sender display can still be spoofed.");
        if (claimedOrganization &&
            claimedOrganization != senderOrganization) {
          f.push_back({"The verified sender organization does not match the "
                       "organization claimed in the message.",
                       35});
          notes.push_back("Sender verification: confirmed organization "
                          "mismatch.");
        }
      }
    } else if (sms) {
      notes.push_back("No sender value supplied; the message and links were "
                      "analyzed without sender verification.");
    }
    const bool amount = std::any_of(words.begin(), words.end(), [](char c) {
      return c >= '0' && c <= '9';
    });
    const bool debitClaim = containsAny(
        words, {"deducted", "detucted", "deduted", "dedcuted", "debited",
                "charged", "withdrawn", "taken from", "deduction"});
    const bool accountContext = containsAny(
        words, {"account", "bank", "card", "balance", "transaction", "wallet"});
    const bool recovery = containsAny(
        words, {"get back", "get it back", "get your money back", "refund",
                "reverse", "recover", "reversal", "dispute"});
    const bool action =
        containsAny(words,
                    {"click here", "click the link", "tap here", "tap the link",
                     "follow the link", "claim now", "call now", "reply now",
                     "click below", "tap below", "click on the link",
                     "visit the link", "call this number", "call us",
                     "text back", "reply yes"}) ||
        (recovery && containsAny(text, {"https://", "http://", "www."}));
    if (debitClaim && accountContext && (amount || recovery) && action) {
      f.push_back(
          {"An alleged debit or charge is used to prompt a recovery action.",
           35});
      if (recovery)
        f.push_back({"A refund or reversal is tied to an immediate click, call "
                     "or reply.",
                     30});
      advice = "Open your banking app independently to check the transaction. "
               "Contact your bank using the number on your card.";
    }
    const bool secretRequest =
        asksForSecret(text) ||
        containsAny(words, {"otp bhejo", "otp bheje", "otp share karo",
                            "otp batao", "otp bhej do", "password bhejo",
                            "password batao", "पासवर्ड बताएं",
                            "पासवर्ड भेजें", "ओटीपी भेजें", "ओटीपी बताएं",
                            "ओटीपी साझा करें"});
    const bool kycRequest =
        containsAny(words, {"update your kyc", "complete kyc", "kyc update",
                            "kyc pending", "kyc verify", "update kyc now",
                            "kyc update karo", "kyc abhi update",
                            "केवाईसी अपडेट करें", "केवाईसी पूरा करें"});
    const bool paymentRequest =
        containsAny(words, {"pay now", "make a payment", "pay the fee",
                            "pay fee", "delivery fee", "redelivery fee",
                            "pay rs ",
                            "send money", "transfer money", "pay to avoid",
                            "payment pending", "भुगतान करें", "पैसे भेजें",
                            "राशि जमा करें", "जुर्माना भरें"});
    const bool installRequest =
        containsAny(words, {"install this app", "install the app",
                            "download this app", "download the app",
                            "install app", "app install karo",
                            "app download karo", "ऐप इंस्टॉल करें",
                            "ऐप डाउनलोड करें"});
    const bool pressure =
        containsAny(words, {"urgent", "immediately", "within 24 hours",
                            "suspended", "suspension", "blocked today",
                            "suspend your account", "account suspend",
                            "final warning", "account will be closed",
                            "account will be blocked", "legal action",
                            "otherwise your account", "turant", "abhi",
                            "account band", "band hoga", "अभी नहीं तो",
                            "खाता बंद", "खाता ब्लॉक", "तुरंत करें"});
    const bool transactionalClaim =
        containsAny(words, {"parcel", "delivery", "shipment", "tracking",
                            "invoice", "order", "bank", "account", "payment",
                            "refund", "subscription", "membership", "kyc",
                            "verification"});
    const bool riskyRequest =
        secretRequest || kycRequest || paymentRequest || installRequest;
    if (secretRequest)
      f.push_back({"The message asks the recipient to share an OTP, password, "
                   "or verification code.",
                   35});
    if (kycRequest)
      f.push_back({"The message asks the recipient to update or complete KYC.",
                   22});
    if (paymentRequest)
      f.push_back({"The message requests a payment or transfer.",
                   containsAny(words, {"wire transfer", "gift card",
                                        "bank details", "credit card"})
                       ? 30
                       : 22});
    if (installRequest)
      f.push_back({"The message asks the recipient to install or download an "
                   "app.",
                   18});
    if (pressure)
      f.push_back({"Urgency, a threat, or an account-suspension claim appears "
                   "in the message.",
                   riskyRequest ? 15 : 8});
    if (pressure && riskyRequest)
      f.push_back({"A risky request is paired with urgency or a threat.", 18});
    if (containsAny(text, {"your parcel", "redelivery", "delivery failed"}) &&
        paymentRequest)
      f.push_back({"A delivery claim is paired with a payment request.", 18});
    if (containsAny(text, {"won a prize", "claim your reward", "lottery"}))
      f.push_back({"Unexpected prize or reward language appears.", 25});
    if (containsAny(text, {".exe", ".scr", "enable macros"}))
      f.push_back({"The message mentions executable content or macros.", 25});
    std::istringstream tokens(sms ? text : body);
    S word;
    LinkQueue links;
    int count = 0;
    while (tokens >> word && count < 32) {
      const S token = lower(word);
      auto pos = token.find("https://");
      if (pos == S::npos)
        pos = token.find("http://");
      if (pos == S::npos)
        pos = token.find("www.");
      if (pos != S::npos) {
        links.push(trimLink(word.substr(pos)));
        ++count;
      }
    }
    if (count &&
        containsAny(text, {"update your kyc", "verify your account",
                           "verify your identity", "reactivate your account",
                           "केवाईसी अपडेट करें", "खाता बंद"}))
      f.push_back(
          {"An account or identity verification request includes a web link.",
           25});
    int flaggedLinks = 0;
    int unrelatedLinks = 0;
    Args flaggedHosts;
    while (!links.empty()) {
      Findings link;
      try {
        const S foundHost = website(links.pop(), link);
        notes.push_back("Message link domain: " + foundHost + ".");
        if (claimedOrganization) {
          if (officialSmsDomain(foundHost, *claimedOrganization)) {
            notes.push_back("The link domain matches a configured official "
                            "domain for " +
                            claimedOrganization->name + ".");
          } else {
            ++unrelatedLinks;
            notes.push_back("The link domain does not match a configured "
                            "official domain for " +
                            claimedOrganization->name + ".");
          }
        }
        if (!link.empty()) {
          ++flaggedLinks;
          if (!linearSearch(flaggedHosts, foundHost) && flaggedHosts.size() < 5)
            flaggedHosts.push_back(foundHost);
        }
      } catch (const Problem &) {
        continue;
      }
    }
    if (unrelatedLinks) {
      f.push_back({std::to_string(unrelatedLinks) +
                       " message link(s) do not match the claimed "
                       "organization's official domains.",
                   sms ? std::min(40, 20 + unrelatedLinks * 5) : 60});
      if (riskyRequest)
        f.push_back({"A risky request is paired with an unrelated link.", 18});
    }
    if (!sms && !claimedOrganization && !sender.empty() &&
        consumerMailboxAddress(sender) && transactionalClaim && count > 0) {
      f.push_back(
          {"A delivery, account, or payment claim from a consumer mailbox "
           "directs the recipient to an unverified external link.",
           51});
      notes.push_back(
          "The sender uses a consumer email provider and the message includes "
          "a service-related link; no official organization-domain match was "
          "established.");
      if (pressure)
        f.push_back(
            {"The unverified service link is paired with urgency or a threat.",
             15});
    }
    if (flaggedLinks) {
      f.push_back({std::to_string(flaggedLinks) +
                       " embedded URL(s) raised structural warnings.",
                   std::min(40, 15 + flaggedLinks * 5)});
      for (const auto &host : flaggedHosts)
        notes.push_back("URL requiring review: " + host);
    }
    notes.push_back("Explicit web links found (up to 32): " +
                    std::to_string(count));
    // Content-only email screening cannot authenticate the sender.
    if (!sms) {
      confidencePenalty += sender.empty() ? 20 : 12;
      if (headers.empty())
        confidencePenalty += 18;
    }
    if (!sms) {
      notes.push_back(sender.empty()
                          ? "No sender address supplied."
                          : "Displayed sender identity is unverified.");
      notes.push_back(
          "Email links are parsed without opening them. Links are compared "
          "with configured official domains when a supported organization is "
          "identified.");
      if (sender.substr(0, sender.find('@')).find("support") != S::npos &&
          containsAny(lower(sender),
                      {"@gmail.com", "@outlook.com", "@yahoo.com"}))
        f.push_back({"A support-style sender uses a consumer mailbox. Confirm "
                     "the organisation independently.",
                     10});
      if (!headers.empty()) {
        std::istringstream lines(headers);
        S line, current;
        S results, replyTo;
        while (std::getline(lines, line)) {
          line = lower(line);
          if (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
            if (current == "authentication-results")
              results += " " + line;
            continue;
          }
          auto sep = line.find(':');
          current = sep == S::npos ? "" : line.substr(0, sep);
          if (current == "authentication-results")
            results += " " + line.substr(sep + 1);
          if (current == "reply-to")
            replyTo = line.substr(sep + 1);
        }
        bool failure = false;
        for (S k : {"spf", "dkim", "dmarc"}) {
          std::smatch match;
          const std::regex check("\\b" + k +
                                 "\\s*=\\s*(pass|fail|softfail|neutral|none|"
                                 "temperror|permerror)\\b");
          S value = std::regex_search(results, match, check) ? match[1].str()
                                                             : "unavailable";
          notes.push_back(k + " in supplied Authentication-Results: " + value +
                          " (unverified).");
          failure |= value == "fail" || value == "softfail";
        }
        if (failure)
          f.push_back(
              {"A supplied header reports an email authentication failure.",
               20});
        if (!sender.empty() && !replyTo.empty()) {
          try {
            S reply = mailbox(replyTo);
            if (reply.substr(reply.find('@') + 1) !=
                sender.substr(sender.find('@') + 1))
              f.push_back({"The Reply-To domain differs from the displayed "
                           "sender domain.",
                           15});
          } catch (const Problem &) {
            notes.push_back(
                "Could not interpret the supplied Reply-To address.");
          }
        }
      } else
        notes.push_back("No authentication headers supplied.");
    }
  }
  if (type == "Email")
    notes.push_back(
        "Missing sender or authentication evidence can limit the assessment. "
        "Supplied headers are parsed as claims and are not cryptographically "
        "verified by CyberShield.");
  sortFindings(f);
  J findings = type == "Software" ? softwareSignals : J::array();
  int score = 0;
  if (type != "Software") {
    for (auto &row : f) {
      findings.push_back({{"text", row.text}, {"points", row.points}});
      score += row.points;
    }
  }
  score = std::min(score, 100);
  const int trustScore = std::max(0, std::min(100, 100 - score - confidencePenalty));
  S category;
  if (type == "SMS" && score >= SmsHighRiskThreshold)
    category = "High risk";
  else if (type == "SMS" && score >= SmsSuspiciousThreshold)
    category = "Suspicious";
  else if (type == "SMS")
    category = "Low risk";
  else if (score >= 60)
    category = "High risk";
  else if (score >= 25)
    category = type == "Software" && !recognizedSource && !hostname.empty()
                   ? "Unverified source"
                   : "Suspicious";
  else if (type == "Software")
    category = recognizedSource
                   ? "Recognized source"
                   : hostname.empty() ? "Insufficient information"
                                      : "Unverified source";
  else
    category = "Lower risk";
  J report = {{"type", type},
              {"target", target},
              {"category", category},
              {"findings", findings},
              {"notes", notes},
              {"advice", advice},
              {"source", source}};
  report["score"] = score;
  report["trust_score"] = type == "Software" ? J(nullptr) : J(trustScore);
  report["confidence_penalty"] = confidencePenalty;
  if (type == "Software")
    report["source_status"] =
        softwareContext.value("source_status", S("UNVERIFIED"));
  if (!basis.empty())
    report["basis"] = basis;
  if (!hostname.empty())
    report["hostname"] = hostname;
  if (type == "Software") {
    if (!submittedSoftwareUrl.empty())
      report["source_url"] = submittedSoftwareUrl;
    if (matchedSource)
      report["source_reference"] =
          {{"source", matchedSource->source},
           {"url", matchedSource->reference}};
    return scoreSoftwareReport(std::move(report), softwareSignals,
                               softwareContext, J::object());
  }
  return report;
}
