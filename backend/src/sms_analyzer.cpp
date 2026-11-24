#include "sms_analyzer.h"

#include "download_source_registry.h"
#include "sms_risk_config.h"
#include "sms_sender_registry.h"
#include "website_inspector.h"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace {
using sms_risk::config::ActionWeight;
using sms_risk::config::ContextWeight;
using sms_risk::config::CautionThreshold;
using sms_risk::config::HighRiskThreshold;
using sms_risk::config::LinkWeight;
using sms_risk::config::MaximumInteractionBonus;
using sms_risk::config::SenderWeight;
using sms_risk::config::UrgencyWeight;

struct Signal {
  S id;
  S name;
  S category;
  S family;
  S severity;
  S explanation;
  S evidence;
  S detectionMethod;
  S verificationStatus;
  int strength = 0;
  int evidenceConfidence = 0;
  int occurrences = 1;
};

struct InteractionResult {
  int score = 0;
  Args reasons;
};

struct LinkCandidate {
  S text;
  S source;
};

struct LinkResult {
  S host;
  S scheme;
  S status;
  std::vector<S> redirectHosts;
  bool parsed = false;
  bool complete = true;
};

static S asciiLower(S value) {
  for (char &c : value)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}

static S cleanSmsText(const S &text) {
  S clean;
  for (size_t i = 0; i < text.size();) {
    const auto starts = [&](const char *bytes, size_t length) {
      return text.compare(i, length, bytes, length) == 0;
    };
    if (starts("\xE2\x80\x8B", 3) || starts("\xE2\x80\x8C", 3) ||
        starts("\xE2\x80\x8D", 3) || starts("\xE2\x80\x8E", 3) ||
        starts("\xE2\x80\x8F", 3) || starts("\xE2\x81\xA0", 3) ||
        starts("\xE2\x81\xA3", 3) || starts("\xE2\x81\xA6", 3) ||
        starts("\xE2\x81\xA7", 3) || starts("\xE2\x81\xA8", 3) ||
        starts("\xE2\x81\xA9", 3) || starts("\xE2\x80\xAA", 3) ||
        starts("\xE2\x80\xAB", 3) || starts("\xE2\x80\xAC", 3) ||
        starts("\xE2\x80\xAD", 3) || starts("\xE2\x80\xAE", 3) ||
        starts("\xEF\xBB\xBF", 3) || starts("\xC2\xAD", 2)) {
      i += starts("\xC2\xAD", 2) ? 2 : 3;
      continue;
    }
    if (starts("\xC2\xA0", 2) || starts("\xE2\x80\xAF", 3)) {
      if (!clean.empty() && clean.back() != ' ')
        clean += ' ';
      i += starts("\xC2\xA0", 2) ? 2 : 3;
      continue;
    }
    const unsigned char c = static_cast<unsigned char>(text[i++]);
    if (c < 0x20 || c == 0x7f) {
      if (!clean.empty() && clean.back() != ' ')
        clean += ' ';
    } else {
      clean += static_cast<char>(c);
    }
  }
  return clean;
}

static S wordsOnly(const S &text) {
  S words;
  for (unsigned char c : asciiLower(text)) {
    if (c == '.' || c == '!' || c == '?' || c == ';' || c == '\n' ||
        c == '\r') {
      if (!words.empty() && words.back() != ' ')
        words += " sentencesplit ";
    } else if (std::isalnum(c) || c >= 0x80) {
      words += static_cast<char>(c);
    } else if (!words.empty() && words.back() != ' ') {
      words += ' ';
    }
  }
  while (!words.empty() && words.back() == ' ')
    words.pop_back();
  return words;
}

static bool hasPhrase(const S &words, const S &phrase) {
  const S needle = wordsOnly(phrase);
  if (needle.empty())
    return false;
  return (" " + words + " ").find(" " + needle + " ") != S::npos;
}

static S firstPhrase(const S &words, const Args &phrases) {
  for (const S &phrase : phrases)
    if (hasPhrase(words, phrase))
      return phrase;
  return {};
}

static bool hasNegationBefore(const S &words, const S &phrase);

static bool negatedBeforeToken(const std::vector<S> &tokens, size_t at) {
  const size_t start = at > 8 ? at - 8 : 0;
  S prefix;
  for (size_t i = start; i < at; ++i) {
    if (tokens[i] == "sentencesplit") {
      prefix.clear();
      continue;
    }
    prefix += (prefix.empty() ? "" : " ") + tokens[i];
  }
  for (const S &negation :
       Args{"do not", "dont", "don't", "never", "not to", "will not",
            "we will never", "mat", "nahi", "na", "न", "नहीं", "मत",
            "कभी न"})
    if (hasPhrase(prefix, negation))
      return true;
  return false;
}

static S actionWithTopic(const S &words, const Args &actions,
                         const Args &topics, size_t maxGap = 4) {
  std::istringstream input(words);
  std::vector<S> tokens;
  S token;
  while (input >> token)
    tokens.push_back(token);
  const auto contains = [](const Args &values, const S &value) {
    return std::find(values.begin(), values.end(), value) != values.end();
  };
  for (size_t i = 0; i < tokens.size(); ++i) {
    if (!contains(actions, tokens[i]) || negatedBeforeToken(tokens, i))
      continue;
    const size_t last = std::min(tokens.size(), i + maxGap + 2);
    for (size_t j = i + 1; j < last; ++j)
      if (contains(topics, tokens[j])) {
        S evidence = tokens[i];
        for (size_t k = i + 1; k <= j; ++k)
          evidence += " " + tokens[k];
        return evidence;
      }
  }
  return {};
}

static S requestedSecretPhrase(const S &words) {
  const S secret = firstPhrase(
      words, {"one time password", "one time code", "verification code",
              "security code", "upi pin", "otp", "password", "passcode",
              "pin"});
  if (secret.empty())
    return {};
  const S evidence = actionWithTopic(
      words,
      {"reply", "send", "share", "provide", "tell", "give", "forward",
       "text", "enter", "type"},
      {"otp", "code", "password", "passcode", "pin"}, 5);
  if (evidence.empty() || hasNegationBefore(words, evidence))
    return {};
  return evidence;
}

static S deadlinePhrase(const S &words) {
  static const std::regex englishDeadline(
      R"(\bwithin\s+[0-9]{1,3}\s+(?:seconds?|secs?|minutes?|mins?|hours?|hrs?)\b)");
  std::smatch match;
  if (std::regex_search(words, match, englishDeadline))
    return match.str();
  static const std::regex hindiDeadline(
      R"(\b[0-9]{1,3}\s+(?:minute|minutes|min|mins|hour|hours|ghante|ghanta)\s+(?:ke andar|mein)\b)");
  if (std::regex_search(words, match, hindiDeadline))
    return match.str();
  return {};
}

static bool hasCurrencyAmount(const S &text) {
  static const std::regex amount(
      R"((₹|rs\.?|inr|usd|\$)\s*[0-9][0-9,]*(\.[0-9]{1,2})?|\b[0-9][0-9,]*(\.[0-9]{1,2})?\s*(rs\.?|inr|usd|rupees?|dollars?)\b)",
      std::regex::icase);
  return std::regex_search(text, amount);
}

static bool anyPhrase(const S &words, const Args &phrases) {
  return !firstPhrase(words, phrases).empty();
}

static bool hasNegationBefore(const S &words, const S &phrase) {
  const S needle = wordsOnly(phrase);
  const S padded = " " + words + " ";
  const S target = " " + needle + " ";
  bool found = false;
  for (size_t at = padded.find(target); at != S::npos;
       at = padded.find(target, at + target.size())) {
    found = true;
    std::istringstream input(padded.substr(0, at));
    std::vector<S> tokens;
    S token;
    while (input >> token)
      tokens.push_back(token);
    if (!negatedBeforeToken(tokens, tokens.size()))
      return false;
  }
  return found;
}

static S firstUnnegatedPhrase(const S &words, const Args &phrases) {
  for (const S &phrase : phrases)
    if (hasPhrase(words, phrase) && !hasNegationBefore(words, phrase))
      return phrase;
  return {};
}

static void addSignal(std::vector<Signal> &signals, const S &id, const S &name,
                      const S &category, const S &family, int strength,
                      int evidenceConfidence, const S &explanation,
                      const S &evidence, const S &detectionMethod,
                      const S &verificationStatus) {
  if (strength <= 0)
    return;
  const auto found = std::find_if(
      signals.begin(), signals.end(), [&](const Signal &signal) {
        return signal.id == id && signal.evidence == evidence;
      });
  if (found != signals.end()) {
    found->occurrences = std::min(3, found->occurrences + 1);
    found->strength = std::max(found->strength, strength);
    found->evidenceConfidence =
        std::max(found->evidenceConfidence, evidenceConfidence);
    return;
  }
  const S severity = strength >= 85   ? "Critical"
                     : strength >= 65 ? "High"
                     : strength >= 40 ? "Moderate"
                     : strength >= 20 ? "Low"
                                      : "Observation";
  signals.push_back({id, name, category, family, severity, explanation,
                     evidence, detectionMethod, verificationStatus,
                     std::min(100, strength),
                     std::min(100, evidenceConfidence), 1});
}

static S trimPunctuation(S value) {
  while (!value.empty() &&
         (value.back() == '.' || value.back() == ',' || value.back() == '!' ||
          value.back() == '?' || value.back() == ';' || value.back() == ':' ||
          value.back() == ')' || value.back() == ']' || value.back() == '}' ||
          value.back() == '"' || value.back() == '\'')) {
    value.pop_back();
  }
  while (!value.empty() &&
         (value.front() == '(' || value.front() == '[' || value.front() == '{' ||
          value.front() == '"' || value.front() == '\'')) {
    value.erase(value.begin());
  }
  return value;
}

static void appendCandidate(std::vector<LinkCandidate> &links, S value,
                            const S &source) {
  value = trimPunctuation(value);
  if (value.empty())
    return;
  const S lowerValue = asciiLower(value);
  const auto duplicate = std::find_if(
      links.begin(), links.end(), [&](const LinkCandidate &link) {
        S previous = asciiLower(link.text);
        const auto canonical = [](S text) {
          text = asciiLower(text);
          if (text.rfind("www.", 0) == 0)
            text = "https://" + text;
          else if (text.find("://") == S::npos)
            text = "https://" + text;
          return text;
        };
        return canonical(previous) == canonical(lowerValue);
      });
  if (duplicate == links.end())
    links.push_back({value, source});
}

static std::vector<LinkCandidate> extractLinks(const S &text) {
  std::vector<LinkCandidate> links;
  std::vector<std::pair<size_t, size_t>> coveredRanges;
  static const std::regex explicitUrl(
      R"((?:[A-Z][A-Z0-9+.-]*://|www\.)[^\s<>"']+)", std::regex::icase);
  static const std::regex domainUrl(
      R"((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?::[0-9]{1,5})?(?:/[^\s<>"']*)?(?:\?[^\s<>"']*)?(?:#[^\s<>"']*)?)",
      std::regex::icase);
  for (std::sregex_iterator it(text.begin(), text.end(), explicitUrl), end;
       it != end; ++it) {
    appendCandidate(links, it->str(), "plain_text");
    const size_t start = static_cast<size_t>(it->position());
    coveredRanges.push_back({start, start + static_cast<size_t>(it->length())});
  }
  static const std::regex encodedUrl(
      R"((?:https?%3a%2f%2f)[^\s<>"']+)", std::regex::icase);
  for (std::sregex_iterator it(text.begin(), text.end(), encodedUrl), end;
       it != end; ++it) {
    appendCandidate(links, it->str(), "percent_encoded");
    const size_t start = static_cast<size_t>(it->position());
    coveredRanges.push_back({start, start + static_cast<size_t>(it->length())});
  }
  for (std::sregex_iterator it(text.begin(), text.end(), domainUrl), end;
       it != end; ++it) {
    const size_t position = static_cast<size_t>(it->position());
    const bool insideExistingUrl =
        std::any_of(coveredRanges.begin(), coveredRanges.end(),
                    [&](const auto &range) {
                      return position >= range.first && position < range.second;
                    });
    if (insideExistingUrl)
      continue;
    if (position > 0) {
      const unsigned char before = static_cast<unsigned char>(text[position - 1]);
      if (std::isalnum(before) || before == '@' || before == '-' ||
          before == '.' || before == '%')
        continue;
    }
    appendCandidate(links, it->str(), "bare_domain");
  }
  if (links.size() > 32)
    links.resize(32);
  return links;
}

static int hexValue(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static S percentDecode(const S &value) {
  S decoded;
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      const int high = hexValue(value[i + 1]);
      const int low = hexValue(value[i + 2]);
      if (high >= 0 && low >= 0) {
        const char byte = static_cast<char>(high * 16 + low);
        if (byte == '\0' || static_cast<unsigned char>(byte) < 0x20)
          return value;
        decoded += byte;
        i += 2;
        continue;
      }
    }
    decoded += value[i];
  }
  return decoded;
}

static S rawHostFromUrl(const S &url) {
  const size_t separator = url.find("://");
  if (separator == S::npos)
    return {};
  const size_t authorityStart = separator + 3;
  size_t authorityEnd = url.find_first_of("/?#", authorityStart);
  if (authorityEnd == S::npos)
    authorityEnd = url.size();
  S authority = url.substr(authorityStart, authorityEnd - authorityStart);
  const size_t userInfo = authority.rfind('@');
  if (userInfo != S::npos)
    authority.erase(0, userInfo + 1);
  if (!authority.empty() && authority.front() == '[') {
    const size_t close = authority.find(']');
    if (close != S::npos)
      return authority.substr(0, close + 1);
  }
  const size_t port = authority.rfind(':');
  if (port != S::npos)
    authority.resize(port);
  return asciiLower(authority);
}

static bool hasNonAscii(const S &value) {
  return std::any_of(value.begin(), value.end(), [](unsigned char c) {
    return c >= 0x80;
  });
}

static bool domainOrSubdomain(const S &host, const S &domain) {
  return host == domain ||
         (host.size() > domain.size() &&
          host.compare(host.size() - domain.size(), domain.size(), domain) ==
              0 &&
          host[host.size() - domain.size() - 1] == '.');
}

static S senderKey(const S &sender) {
  S result;
  for (unsigned char c : asciiLower(sender))
    if (std::isalnum(c))
      result += static_cast<char>(c);
  return result;
}

static const SmsOrganization *findSenderOrganization(const S &sender) {
  const S normalized = senderKey(sender);
  if (normalized.empty())
    return nullptr;
  for (const SmsOrganization &organization : smsOrganizationRegistry()) {
    for (const S &id : organization.senderIds)
      if (normalized == senderKey(id))
        return &organization;
    for (const S &number : organization.phoneNumbers)
      if (normalized == senderKey(number))
        return &organization;
  }
  return nullptr;
}

static const SmsOrganization *findClaimedOrganization(const S &words) {
  for (const SmsOrganization &organization : smsOrganizationRegistry()) {
    if (hasPhrase(words, organization.name))
      return &organization;
    for (const S &alias : organization.aliases)
      if (hasPhrase(words, alias))
        return &organization;
  }
  return nullptr;
}

static bool officialDomain(const S &host,
                           const SmsOrganization &organization) {
  for (const S &domain : organization.officialDomains)
    if (domainOrSubdomain(host, asciiLower(domain)))
      return true;
  return false;
}

static bool isShortener(const S &host) {
  static const Args shorteners = {
      "bit.ly",      "t.co",          "tinyurl.com", "is.gd",
      "cutt.ly",     "rb.gy",         "shorturl.at", "rebrand.ly",
      "ow.ly",       "buff.ly",       "lnkd.in",     "goo.gl",
      "short.io",    "s.id",          "t.ly",        "tiny.cc"};
  return std::find(shorteners.begin(), shorteners.end(), host) !=
         shorteners.end();
}

static std::vector<S> redirectHosts(const website_inspector::ParsedUrl &url,
                                    const S &outerHost) {
  std::vector<S> hosts;
  const size_t query = url.url.find('?');
  if (query == S::npos)
    return hosts;
  const size_t end = url.url.find('#', query + 1);
  const S queryText = url.url.substr(
      query + 1, end == S::npos ? S::npos : end - query - 1);
  std::istringstream pairs(queryText);
  S pair;
  while (std::getline(pairs, pair, '&')) {
    const size_t equal = pair.find('=');
    if (equal == S::npos)
      continue;
    const S key = asciiLower(percentDecode(pair.substr(0, equal)));
    if (key != "url" && key != "redirect" && key != "redirect_url" &&
        key != "redirect_uri" && key != "next" && key != "target" &&
        key != "continue" && key != "dest" && key != "destination")
      continue;
    S value = percentDecode(pair.substr(equal + 1));
    if (value.rfind("//", 0) == 0)
      value = "https:" + value;
    else if (value.rfind("www.", 0) == 0)
      value = "https://" + value;
    else if (value.find("://") == S::npos &&
             value.find('.') != S::npos)
      value = "https://" + value;
    website_inspector::ParsedUrl nested;
    S error;
    if (website_inspector::parseUrl(value, nested, error) &&
        !nested.host.empty() && nested.host != outerHost &&
        std::find(hosts.begin(), hosts.end(), nested.host) == hosts.end())
      hosts.push_back(nested.host);
  }
  return hosts;
}

static LinkResult inspectUrl(const LinkCandidate &candidate,
                             const SmsOrganization *claimed,
                             std::vector<Signal> &signals) {
  LinkResult result;
  S candidateText = trimPunctuation(candidate.text);
  const bool percentEncoded = candidateText.find("%3a") != S::npos ||
                              candidateText.find("%3A") != S::npos;
  if (candidate.source == "percent_encoded" || percentEncoded)
    candidateText = percentDecode(candidateText);
  S parseText = candidateText;
  const size_t schemeSeparator = parseText.find("://");
  const S scheme = schemeSeparator == S::npos
                       ? S()
                       : asciiLower(parseText.substr(0, schemeSeparator));
  result.scheme = scheme.empty() ? "https" : scheme;
  if (scheme.empty()) {
    if (parseText.rfind("//", 0) == 0)
      parseText = "https:" + parseText;
    else if (parseText.rfind("www.", 0) == 0)
      parseText = "https://" + parseText;
    else
      parseText = "https://" + parseText;
  }
  if (!scheme.empty() && scheme != "http" && scheme != "https") {
    result.host = rawHostFromUrl(parseText);
    result.status = "unsupported_scheme";
    result.complete = false;
    const int strength = scheme == "javascript" || scheme == "data" ? 85 : 35;
    addSignal(signals, "unsupported_link_scheme", "Unsupported link scheme",
              "link_destination", "unsupported_scheme", strength, 88,
              "The pasted link does not use HTTP or HTTPS, so its web "
              "destination could not be checked.",
              scheme + " scheme", "URL parser", "unknown");
    return result;
  }
  const S rawHost = rawHostFromUrl(parseText);
  if (rawHost.find('%') != S::npos)
    addSignal(signals, "encoded_hostname", "Encoded hostname characters",
              "link_destination", "hostname_obfuscation", 72, 81,
              "Percent encoding appears in the raw hostname and can obscure "
              "the destination.",
              rawHost, "URL structure parser", "heuristic");
  website_inspector::ParsedUrl parsed;
  S error;
  if (!website_inspector::parseUrl(parseText, parsed, error)) {
    result.status = "parse_failed";
    result.complete = false;
    result.host = rawHostFromUrl(parseText);
    const bool unicodeHost = hasNonAscii(result.host);
    if (unicodeHost)
      addSignal(signals, "unicode_host_unresolved",
                "Unicode hostname needs normalization", "link_destination",
                "hostname_obfuscation", 58, 52,
                "The domain contains Unicode characters that the local URL "
                "parser could not normalize; its registered domain is "
                "unknown.",
                result.host, "URL parser", "unknown");
    else
      addSignal(signals, "url_parse_incomplete", "Link could not be parsed",
                "link_destination", "unparsed_link", 24, 45,
                "A link-like value was found, but its destination could not "
                "be parsed; this is incomplete analysis, not a safe result.",
                error.empty() ? candidateText : error, "URL parser",
                "unknown");
    return result;
  }
  result.parsed = true;
  result.host = asciiLower(parsed.host);
  result.scheme = parsed.scheme;
  result.status = percentEncoded ? "decoded_for_analysis" : "analyzed";

  if (parsed.hasUserInfo)
    addSignal(signals, "url_userinfo", "Hidden URL user information",
              "link_destination", "destination_obscuring", 78, 88,
              "Text before the @ symbol can make a different hostname look "
              "like the destination.",
              result.host, "URL structure parser", "heuristic");
  if (percentEncoded)
    addSignal(signals, "url_percent_encoded", "Percent-encoded link",
              "link_destination", "destination_obscuring", 56, 70,
              "The URL used an encoded scheme or destination and was decoded "
              "once for local analysis.",
              result.host, "URL structure parser", "heuristic");
  if (hasNonAscii(rawHost))
    addSignal(signals, "unicode_hostname", "Unicode hostname",
              "link_destination", "hostname_obfuscation", 52, 65,
              "The hostname contains Unicode characters; visually similar "
              "letters can be difficult to distinguish.",
              result.host, "URL structure parser", "heuristic");
  if (result.host.find("xn--") != S::npos)
    addSignal(signals, "punycode_hostname", "Encoded international hostname",
              "link_destination", "hostname_obfuscation", 42, 70,
              "The hostname uses punycode. This is not proof of abuse, but "
              "the displayed spelling should be checked.",
              result.host, "URL structure parser", "heuristic");
  if (parsed.isIp)
    addSignal(signals, "ip_host", "Numeric IP address as link host",
              "link_destination", "host_anomaly", 76, 90,
              "The URL points directly to a numeric address instead of a "
              "recognizable domain.",
              result.host, "URL structure parser", "heuristic");
  if (parsed.scheme == "http")
    addSignal(signals, "unencrypted_http", "Unencrypted HTTP link",
              "link_destination", "transport_anomaly", 34, 96,
              "The link does not use HTTPS; this does not by itself prove "
              "that the message is a scam.",
              result.host, "URL structure parser", "verified_from_text");
  if (!parsed.port.empty() &&
      parsed.port != (parsed.scheme == "https" ? "443" : "80"))
    addSignal(signals, "nonstandard_port", "Nonstandard web port",
              "link_destination", "host_anomaly", 40, 88,
              "The URL uses a non-default port, which is uncommon for a "
              "consumer message link.",
              result.host, "URL structure parser", "verified_from_text");
  if (isShortener(result.host))
    addSignal(signals, "shortened_link", "Shortened link destination",
              "link_destination", "hidden_destination", 62, 96,
              "This shortener hides the final destination; CyberShield did "
              "not follow or expand it.",
              result.host, "URL structure parser", "verified_from_text");
  const int labels =
      static_cast<int>(std::count(result.host.begin(), result.host.end(), '.')) +
      1;
  if (labels >= 5)
    addSignal(signals, "deep_subdomain", "Deep subdomain structure",
              "link_destination", "host_anomaly", 38, 90,
              "Several subdomains make the registered domain harder to "
              "notice.",
              result.host, "URL structure parser", "verified_from_text");
  if (result.host.size() > 100)
    addSignal(signals, "long_hostname", "Unusually long hostname",
              "link_destination", "host_anomaly", 36, 90,
              "The hostname is unusually long and may be difficult to read.",
              result.host, "URL structure parser", "verified_from_text");

  static const Args riskySuffixes = {".zip", ".click", ".top", ".work",
                                     ".support", ".gq", ".tk", ".ml",
                                     ".cf",  ".xyz",   ".online", ".site"};
  for (const S &suffix : riskySuffixes) {
    if (result.host.size() > suffix.size() &&
        result.host.compare(result.host.size() - suffix.size(), suffix.size(),
                            suffix) == 0) {
      addSignal(signals, "uncommon_domain_suffix", "Uncommon domain suffix",
                "link_destination", "domain_context", 27, 55,
                "The domain uses a suffix that can be inexpensive to register; "
                "the suffix alone does not establish maliciousness.",
                suffix, "URL structure heuristic", "heuristic");
      break;
    }
  }

  bool brandLookalike = false;
  for (const DownloadSourceEntry &source : downloadSourceRegistry()) {
    if (result.host == source.host || domainOrSubdomain(result.host, source.host))
      continue;
    if (result.host.find(source.host) != S::npos)
      brandLookalike = true;
    for (const DownloadSourceHost &alias : source.aliases)
      if (result.host.find(alias.host) != S::npos &&
          !domainOrSubdomain(result.host, alias.host))
        brandLookalike = true;
  }
  if (claimed) {
    if (!officialDomain(result.host, *claimed)) {
      addSignal(signals, "claimed_organization_domain_mismatch",
                "Link differs from the claimed organization's domains",
                "link_destination", "claimed_domain_mismatch", 82, 90,
                "The message mentions " + claimed->name +
                    ", but this link host is not in its configured official "
                    "domain references. The destination was not opened.",
                result.host, "Configured domain comparison",
                "configured_reference_comparison");
    }
  } else if (brandLookalike) {
    addSignal(signals, "publisher_lookalike",
              "Publisher name embedded in another hostname",
              "link_destination", "brand_lookalike", 78, 87,
              "A configured publisher domain appears inside a different "
              "hostname; compare the registered domain from right to left.",
              result.host, "URL structure heuristic", "heuristic");
  }

  const S path = wordsOnly(parsed.path);
  if (anyPhrase(path, {"login", "signin", "verify account", "password",
                       "payment", "wallet", "kyc"}) &&
      (result.host.find('-') != S::npos || labels >= 4))
    addSignal(signals, "sensitive_path_complex_host",
              "Sensitive path on a complex hostname", "link_destination",
              "credential_lure", 48, 73,
              "An account, payment or verification path is paired with a "
              "complex hostname.",
              result.host + parsed.path, "URL structure heuristic",
              "heuristic");

  result.redirectHosts = redirectHosts(parsed, result.host);
  for (const S &redirectHost : result.redirectHosts)
    addSignal(signals, "redirect_parameter",
              "Link contains a different redirect destination",
              "link_destination", "redirect_parameter", 65, 78,
              "A URL parameter names another host. This destination was "
              "parsed locally but no redirect was followed.",
              result.host + " -> " + redirectHost,
              "URL query inspection", "heuristic");
  return result;
}

static int bounded(int value) { return std::max(0, std::min(100, value)); }

static std::map<S, int> categoryScores(const std::vector<Signal> &signals) {
  std::map<S, std::map<S, int>> families;
  for (const Signal &signal : signals) {
    int &strength = families[signal.category][signal.family];
    strength = std::max(strength, signal.strength);
  }
  std::map<S, int> result = {{"link_destination", 0},
                             {"sender_impersonation", 0},
                             {"requested_action_financial", 0},
                             {"urgency_pressure", 0},
                             {"context_suspiciousness", 0}};
  for (const auto &category : families) {
    double remaining = 1.0;
    for (const auto &family : category.second)
      remaining *= 1.0 - static_cast<double>(family.second) / 100.0;
    result[category.first] =
        bounded(static_cast<int>(std::lround((1.0 - remaining) * 100.0)));
  }
  return result;
}

static int weightedScore(const std::map<S, int> &scores) {
  const long weighted =
      static_cast<long>(scores.at("link_destination")) * LinkWeight +
      static_cast<long>(scores.at("sender_impersonation")) * SenderWeight +
      static_cast<long>(scores.at("requested_action_financial")) *
          ActionWeight +
      static_cast<long>(scores.at("urgency_pressure")) * UrgencyWeight +
      static_cast<long>(scores.at("context_suspiciousness")) * ContextWeight;
  return bounded(static_cast<int>(std::lround(weighted / 100.0)));
}

static InteractionResult interactionAssessment(
    const std::map<S, int> &scores) {
  InteractionResult result;
  const auto interaction = [&](const S &left, const S &right, int weight,
                               int minimum, const S &label) {
    const int a = scores.at(left);
    const int b = scores.at(right);
    if (a < minimum || b < minimum)
      return 0;
    const int points =
        static_cast<int>(std::lround(std::min(a, b) * weight / 100.0));
    if (points > 0)
      result.reasons.push_back(label + ": +" + std::to_string(points));
    return points;
  };
  const int subtotal =
      interaction("urgency_pressure", "requested_action_financial",
                  sms_risk::config::UrgencyActionInteractionWeight, 35,
                  "Urgency with a sensitive request") +
      interaction("link_destination", "requested_action_financial",
                  sms_risk::config::LinkActionInteractionWeight, 35,
                  "Link risk with a requested action") +
      interaction("link_destination", "sender_impersonation",
                  sms_risk::config::LinkSenderInteractionWeight, 45,
                  "Link risk with sender mismatch") +
      interaction("sender_impersonation", "requested_action_financial",
                  sms_risk::config::SenderActionInteractionWeight, 45,
                  "Sender mismatch with a requested action");
  result.score = std::min(MaximumInteractionBonus, subtotal);
  if (subtotal > MaximumInteractionBonus)
    result.reasons.push_back("Combined interaction adjustment capped at " +
                             std::to_string(MaximumInteractionBonus));
  return result;
}

static S severityFor(int strength) {
  return strength >= 85   ? "Critical"
         : strength >= 65 ? "High"
         : strength >= 40 ? "Moderate"
         : strength >= 20 ? "Low"
                          : "Observation";
}

static S classificationFor(int score) {
  if (score >= HighRiskThreshold)
    return "Highly Risky";
  if (score >= CautionThreshold)
    return "Be Cautious";
  return "Safe";
}

static S summaryFor(const std::vector<Signal> &signals, int score) {
  if (signals.empty())
    return "No strong scam indicators were found in the pasted text. This "
           "does not authenticate the sender or prove that the message is safe.";
  std::vector<const Signal *> sorted;
  for (const Signal &signal : signals)
    sorted.push_back(&signal);
  std::sort(sorted.begin(), sorted.end(), [](const Signal *left,
                                             const Signal *right) {
    return left->strength > right->strength;
  });
  S summary = "The " + classificationFor(score) +
              " score reflects ";
  summary += sorted[0]->name;
  if (sorted.size() > 1)
    summary += " and " + sorted[1]->name;
  summary += ".";
  return summary;
}

static int confidenceScore(const std::vector<Signal> &signals,
                           bool linksComplete) {
  if (signals.empty())
    return 35;
  int confidence = 0;
  std::set<S> independentFamilies;
  for (const Signal &signal : signals) {
    confidence = std::max(confidence, signal.evidenceConfidence);
    independentFamilies.insert(signal.family);
  }
  confidence += std::min(10, std::max(0,
                                     static_cast<int>(independentFamilies.size()) -
                                         1) *
                                  3);
  if (!linksComplete)
    confidence -= 8;
  return std::max(25, std::min(95, confidence));
}

static S confidenceLabel(int confidence) {
  if (confidence >= 80)
    return "Strong evidence match";
  if (confidence >= 60)
    return "Moderate evidence match";
  return "Limited evidence";
}

static J signalJson(const Signal &signal) {
  return {{"id", signal.id},
          {"name", signal.name},
          {"category", signal.category},
          {"severity", signal.severity},
          {"text", signal.explanation},
          {"evidence", signal.evidence},
          {"detection_method", signal.detectionMethod},
          {"verification_status", signal.verificationStatus},
          {"occurrences", signal.occurrences}};
}
} // namespace

J analyzeSms(const J &input) {
  const S body = field(input, "content", 5000);
  S sender = field(input, "sender", 128, false);
  if (sender.empty())
    sender = field(input, "phone", 32, false);
  const S clean = cleanSmsText(body);
  if (clean.empty())
    throw Problem(400, "Paste an SMS message to analyze.");
  const S normalized = wordsOnly(clean);
  const SmsOrganization *claimed = findClaimedOrganization(normalized);
  const SmsOrganization *senderOrganization =
      findSenderOrganization(sender);
  std::vector<LinkCandidate> candidates = extractLinks(clean);

  std::vector<Signal> signals;
  std::vector<S> positiveEvidence;
  std::vector<S> notes = {
      "Analysis is local. Pasted links are parsed but never opened or followed.",
      "Sender display values are user-provided and are not authenticated by "
      "this checker."};
  if (claimed) {
    notes.push_back("The message mentions " + claimed->name +
                    "; this is a text claim, not verified authorship.");
  }

  J senderAssessment = {{"provided", !sender.empty()},
                       {"status", "not_provided"},
                       {"claimed_organization",
                        claimed ? J(claimed->name) : J(nullptr)},
                       {"verification",
                        "A displayed sender value cannot be authenticated "
                        "from pasted SMS text."}};
  if (!sender.empty()) {
    if (!senderOrganization) {
      senderAssessment["status"] = "unverified";
      notes.push_back(
          "Sender verification is unknown: the exact supplied value is not "
          "in the local verified sender registry. A brand-looking label is "
          "not proof of ownership.");
    } else {
      senderAssessment["status"] = "configured_registry_match";
      senderAssessment["registry_organization"] = senderOrganization->name;
      senderAssessment["verification"] =
          "The sender value matches a configured registry entry, but SMS "
          "sender display can still be spoofed; this is not authentication.";
      if (claimed && senderOrganization != claimed) {
        senderAssessment["status"] = "registry_claim_mismatch";
        senderAssessment["verification"] =
            "The configured sender entry differs from the organization "
            "mentioned in the message. This comparison does not authenticate "
            "the actual SMS origin.";
        notes.push_back("Configured sender registry mismatch: the sender "
                        "entry is for " +
                        senderOrganization->name + ", while the text mentions " +
                        claimed->name + ".");
        addSignal(signals, "sender_registry_claim_mismatch",
                  "Sender registry differs from the claimed organization",
                  "sender_impersonation", "sender_claim_mismatch", 86, 85,
                  "The supplied sender value matches a configured entry for " +
                      senderOrganization->name + ", while the message claims " +
                      claimed->name +
                      ". Registry comparison is not proof of the actual SMS "
                      "origin.",
                  senderOrganization->name + " vs " + claimed->name,
                  "Configured sender registry comparison",
                  "configured_reference_comparison");
      } else {
        positiveEvidence.push_back(
            "The displayed sender matches a configured registry value for " +
            senderOrganization->name +
            "; this match does not authenticate the message.");
      }
    }
  } else {
    notes.push_back(
        "No sender value was supplied; sender identity could not be compared.");
  }

  const S credentialPhrase = firstUnnegatedPhrase(
      normalized,
      {"send us your otp", "send your otp", "share your otp",
       "tell us your otp", "reply with your otp", "give us the otp",
       "send us the otp", "share the otp", "enter your otp",
       "send otp", "share otp",
       "send us the verification code", "send the verification code",
       "share the verification code", "provide the verification code",
       "reply with the verification code", "send us the security code",
       "send your password", "share your password", "tell us your password",
       "share your pin", "send your pin", "enter your upi pin",
       "share your upi pin", "otp bhejo", "otp bheje", "otp bhej do",
       "otp share karo", "otp batao", "password bhejo", "password batao",
       "otp share kar do", "upi pin bhejo", "अपना ओटीपी भेजें", "ओटीपी भेजें", "ओटीपी बताएं",
       "ओटीपी साझा करें", "पासवर्ड भेजें", "पासवर्ड बताएं"});
  const S requestedSecret =
      credentialPhrase.empty() ? requestedSecretPhrase(normalized)
                               : credentialPhrase;
  const bool credentialRequest =
      !requestedSecret.empty() &&
      !hasNegationBefore(normalized, requestedSecret);
  if (credentialRequest) {
    const bool share = anyPhrase(
        wordsOnly(requestedSecret),
        {"send", "share", "tell", "reply", "give", "bhejo", "bheje",
         "batao", "provide", "forward", "text", "enter", "type",
         "भेजें", "बताएं", "साझा करें"});
    addSignal(
        signals, "credential_sharing_request",
        "Request to share a secret or verification code",
        "requested_action_financial", "credential_request",
        share ? 100 : 76, 94,
        "The message asks the recipient to send, share, tell or enter an OTP, "
        "password or PIN. Legitimate OTP notices normally tell users not to "
        "share codes.",
        requestedSecret, "Contextual message pattern", "heuristic");
  }

  const S kycPhrase = firstUnnegatedPhrase(
      normalized,
      {"update your kyc", "complete your kyc", "complete kyc", "update kyc now",
       "update kyc", "verify your kyc", "submit kyc", "kyc update karo",
       "kyc abhi update", "kyc poora karo",
       "अपना केवाईसी अपडेट करें", "केवाईसी अपडेट करें",
       "केवाईसी पूरा करें", "केवाईसी सत्यापित करें"});
  const bool kycRequest =
      !kycPhrase.empty() && !hasNegationBefore(normalized, kycPhrase);
  S accountActionPhrase = firstUnnegatedPhrase(
      normalized,
      {"verify your account", "verify account now", "reactivate your account",
       "restore your account", "confirm your account", "update bank details",
        "review your account status", "complete the security review",
        "complete security review", "review account status",
        "check your account status", "restore account access",
       "update your bank details", "confirm your card details",
       "reactivate account", "verify identity now", "verify your identity",
       "verify identity", "confirm your identity", "account verify karo",
       "खाता सत्यापित करें", "खाता फिर से चालू करें"});
  if (accountActionPhrase.empty())
    accountActionPhrase = actionWithTopic(
        normalized, {"verify", "confirm", "restore", "reactivate"},
        {"identity", "account"});
  const bool accountAction =
      !accountActionPhrase.empty() &&
      !hasNegationBefore(normalized, accountActionPhrase);
  if (kycRequest)
    addSignal(signals, "account_or_kyc_action",
              "Request to update or complete KYC",
              "requested_action_financial", "kyc_update_request", 66, 85,
              "The message asks the recipient to change, complete or submit "
              "KYC information. This is a risk-relevant request, not proof of "
              "fraud by itself.",
              kycPhrase, "Contextual message pattern", "heuristic");
  if (accountAction)
    addSignal(signals, "account_or_kyc_action",
              "Request to verify or restore an account",
              "requested_action_financial", "account_verification_action",
              58, 85,
              "The message asks the recipient to verify an identity or "
              "restore an account. This is a risk-relevant request, not proof "
              "of fraud by itself.",
              accountActionPhrase, "Contextual message pattern", "heuristic");

  S paymentPhrase = firstUnnegatedPhrase(
      normalized,
      {"pay now", "pay the fee", "pay fee", "pay your bill", "pay the bill",
        "pending payment", "pending transaction", "payment of rs",
        "payment requires confirmation", "requires confirmation today",
       "pay delivery fee",
       "pay the delivery fee", "pay a delivery fee", "pay redelivery fee",
       "pay the redelivery fee",
       "pay the outstanding amount", "pay outstanding bill",
       "make a payment", "send money", "transfer money", "pay using upi",
       "scan this qr", "scan qr code", "pay to avoid", "pay challan",
       "pay the challan", "pay processing fee", "pay registration fee",
       "pay upfront", "pay rs", "pay inr", "pay the amount",
       "complete the pending transaction", "finish the pending transaction",
       "submit the pending payment", "settle the pending transaction",
       "release the pending payment", "pay the pending security fee",
       "भुगतान करें", "पैसे भेजें", "राशि जमा करें", "जुर्माना भरें",
       "फीस भरें", "पैसे जमा करें"});
  if (paymentPhrase.empty())
    paymentPhrase = actionWithTopic(
        normalized,
        {"pay", "make", "send", "transfer", "settle", "deposit", "submit"},
        {"fee", "fees", "payment", "bill", "invoice", "amount", "money",
         "rs", "inr", "upi", "fine", "challan", "subscription", "renewal"});
  const bool paymentRequest =
      !paymentPhrase.empty() &&
      !hasNegationBefore(normalized, paymentPhrase);
  if (paymentRequest) {
    const int strength =
        anyPhrase(normalized, {"delivery", "parcel", "fee", "processing",
                               "challan", "refund", "security", "pending",
                               "transaction", "payment"})
            ? 72
            : 62;
    addSignal(signals, "payment_or_transfer_request",
              "Request for a payment or money transfer",
              "requested_action_financial", "financial_request", strength,
              84,
              "The message asks the recipient to pay, transfer money or "
              "complete a fee. Payment words without a requested action are "
              "not treated as this signal.",
              paymentPhrase, "Contextual message pattern", "heuristic");
  }

  const S installPhrase = firstUnnegatedPhrase(
      normalized,
      {"install this app", "install the app", "download this app",
       "download the app", "install app", "download apk",
       "install anydesk", "install teamviewer", "download anydesk",
       "download teamviewer", "install quick support",
       "install this security app", "install the security app",
       "download this security app", "install the application",
       "app install karo", "app download karo", "ऐप इंस्टॉल करें",
       "ऐप डाउनलोड करें"});
  const bool installRequest =
      !installPhrase.empty() && !hasNegationBefore(normalized, installPhrase);
  const bool remoteAccess = anyPhrase(
      normalized,
      {"anydesk", "teamviewer", "quick support", "rustdesk",
       "remote access", "screen sharing", "screen share"});
  if (installRequest)
    addSignal(signals, "app_install_request", "Request to install an app",
              "requested_action_financial", "app_install_request",
              remoteAccess ? 100 : 64, remoteAccess ? 90 : 82,
              remoteAccess
                  ? "The message asks the recipient to install or use remote "
                    "access software, which can expose a device during a "
                    "financial interaction."
                  : "The message asks the recipient to install or download an "
                    "app; verify the request independently before installing.",
              installPhrase,
              "Contextual message pattern", "heuristic");

  const S contactPhrase = firstPhrase(
      normalized,
      {"call this number", "call the number below", "whatsapp this number",
       "message this number", "reply to this number", "call us now",
       "call the number in this message", "call this mobile number"});
  const bool contactRequest =
      !contactPhrase.empty() &&
      !hasNegationBefore(normalized, contactPhrase);
  const bool financialContext =
      anyPhrase(normalized, {"bank", "account", "upi", "payment", "refund",
                             "kyc", "otp", "card", "money", "parcel",
                             "delivery", "challan", "electricity"});
  if (contactRequest && financialContext)
    addSignal(signals, "alternate_contact_request",
              "Request to use a contact number in the message",
              "requested_action_financial", "alternate_contact", 56, 72,
              "The message asks the recipient to contact a number supplied in "
              "the message. No number ownership was verified.",
              contactPhrase, "Contextual message pattern", "unverified");

  const S awardPhrase = firstUnnegatedPhrase(
      normalized, {"reward", "prize", "giveaway", "lottery", "sweepstakes",
                   "winnings", "gift"});
  const bool awardSelectionDenied =
      anyPhrase(normalized, {"no winner has been selected",
                             "no winner was selected",
                             "not selected as a winner",
                             "you were not selected"});
  const S awardSelectionPhrase =
      awardSelectionDenied
          ? S()
          : firstUnnegatedPhrase(
                normalized,
                {"selected as a winner", "selected for", "chosen as a winner",
                 "chosen for", "you are a winner", "you have won",
                 "winner selected"});
  const bool monetaryAward =
      !awardPhrase.empty() && hasCurrencyAmount(clean);
  const S awardExpiryPhrase = firstUnnegatedPhrase(
      normalized, {"expires today", "will expire", "will expire today",
                   "expires within", "expires in", "expiring today",
                   "claim expires", "eligibility will expire"});
  S awardActionPhrase = firstUnnegatedPhrase(
      normalized,
      {"claim your reward", "claim the reward", "claim a reward",
       "claim reward", "claim your prize", "claim the prize", "claim a prize",
       "claim prize", "your claim expires", "claim expires",
       "redeem your reward", "redeem your prize", "activate your reward",
       "verify your eligibility", "verify eligibility",
       "confirm your eligibility", "verify your reward", "verify the reward",
       "verify your prize", "verify the prize", "collect your reward",
       "collect your prize"});
  if (awardActionPhrase.empty())
    awardActionPhrase = actionWithTopic(
        normalized, {"claim", "redeem", "activate", "verify", "confirm",
                     "collect"},
        {"reward", "prize", "eligibility", "winnings", "benefit", "claim"},
        5);
  if (!awardActionPhrase.empty() &&
      hasNegationBefore(normalized, awardActionPhrase))
    awardActionPhrase.clear();
  const bool awardReady =
      anyPhrase(normalized, {"reward is ready", "prize is ready",
                             "reward is pending verification",
                             "prize is pending verification"});
  const bool awardAction =
      !awardPhrase.empty() && !awardActionPhrase.empty();
  const bool awardContext =
      !awardPhrase.empty() &&
      (!awardSelectionPhrase.empty() || monetaryAward || awardAction ||
       !awardExpiryPhrase.empty() || awardReady);

  S urgencyPhrase = firstPhrase(
      normalized,
      {"immediately", "urgent", "within 24 hours", "today only",
       "act now", "last chance", "final warning", "hurry", "right now",
       "expires today", "will expire", "expiring today", "claim expires",
       "eligibility will expire", "turant", "abhi", "aaj hi", "अभी",
       "तुरंत", "आज ही"});
  if (urgencyPhrase.empty())
    urgencyPhrase = deadlinePhrase(normalized);
  S threatPhrase = firstPhrase(
      normalized,
      {"account will be suspended", "account will be blocked",
       "account suspended", "account is suspended", "account blocked",
       "account is blocked", "account has been blocked",
       "account access has been restricted",
       "permanent account suspension", "permanently suspended",
       "temporarily restricted", "permanently restricted",
       "account access is restricted", "account compromise",
       "security review is pending", "pending security review",
       "account will be closed",
       "sim will be deactivated", "sim deactivation", "sim will be blocked",
       "electricity will be disconnected", "connection will be disconnected",
       "legal action", "police action", "arrest warrant",
       "service will be deactivated", "otherwise your account",
       "account band hoga", "account turant band hoga",
       "aapka account turant band hoga", "account band ho jayega",
       "sim band hoga", "खाता बंद हो जाएगा", "खाता ब्लॉक हो जाएगा",
       "कनेक्शन काट दिया जाएगा"});
  if (threatPhrase.empty()) {
    const bool accountMention =
        anyPhrase(normalized, {"account", "account access", "bank account",
                               "sim", "khata", "खाता"});
    const S consequence = firstPhrase(
        normalized,
        {"suspended", "suspension", "suspend", "blocked", "blocking",
         "deactivated", "deactivation", "restricted", "restriction",
         "frozen", "freeze", "closed", "closure", "band hoga",
         "band ho jayega", "block ho jayega", "खाता बंद", "खाता ब्लॉक"});
    if (accountMention && !consequence.empty() &&
        !hasNegationBefore(normalized, consequence))
      threatPhrase = "account + " + consequence;
  }
  if (!threatPhrase.empty() && hasNegationBefore(normalized, threatPhrase))
    threatPhrase.clear();
  if (threatPhrase.empty() &&
      anyPhrase(normalized, {"account", "khata", "खाता"}) &&
      anyPhrase(normalized, {"band hoga", "block hoga", "band ho jayega",
                             "block ho jayega"}))
    threatPhrase = "account + band hoga";
  const bool urgent = !urgencyPhrase.empty();
  const bool threat = !threatPhrase.empty();
  const bool riskyAction =
      credentialRequest || kycRequest || accountAction || paymentRequest ||
      installRequest || contactRequest || awardAction;
  if (urgent || threat) {
    const int pressureStrength =
        (threat && riskyAction) ? 100
        : (threat && !candidates.empty()) ? 62
        : (urgent && riskyAction) ? 72
        : threat                ? 38
                                : 12;
    const S evidence =
        threat ? threatPhrase : urgencyPhrase;
    addSignal(signals, "urgency_or_threat",
              threat ? "Threat or account consequence"
                     : "Urgency or time pressure",
              "urgency_pressure", "pressure_language", pressureStrength,
              threat ? 84 : 62,
              threat && riskyAction
                  ? "A threat or account consequence is paired with a "
                    "requested action."
                  : threat
                        ? "A consequence or threat appears, but pressure alone "
                          "does not establish that the message is fraudulent."
                        : riskyAction
                              ? "A time-pressure phrase is paired with a "
                                "requested action."
                              : "Urgent wording appears without a risky "
                                "request; urgency by itself is weak evidence.",
              evidence, "Contextual message pattern", "heuristic");
  }
  const bool deliveryClaim =
      anyPhrase(normalized, {"parcel", "delivery", "redelivery", "shipment",
                             "courier", "tracking", "package"});
  const bool debitClaim = anyPhrase(
      normalized, {"debited", "deducted", "charged", "withdrawn",
                   "transaction failed", "amount deducted"});
  const bool recoveryClaim =
      anyPhrase(normalized, {"refund", "reverse the transaction",
                             "recover your money", "get your money back",
                             "refund your amount", "reversal"});
  const bool prizeClaim =
      anyPhrase(normalized, {"won a prize", "claim your reward", "lottery",
                             "lucky winner", "reward winner"});
  const bool jobOrLoanClaim =
      anyPhrase(normalized, {"job offer", "work from home", "loan approved",
                             "instant loan", "guaranteed returns",
                             "investment opportunity"});
  const bool upfrontFee =
      anyPhrase(normalized, {"registration fee", "processing fee",
                             "advance fee", "upfront fee", "pay upfront"});

  if (deliveryClaim && paymentRequest && candidates.empty())
    addSignal(signals, "delivery_fee_lure", "Delivery claim paired with a fee",
              "context_suspiciousness", "delivery_fee_lure", 72, 81,
              "The message uses a parcel or delivery claim to request a fee. "
              "Check delivery status through the carrier's official app.",
              firstPhrase(normalized, {"delivery", "parcel", "courier"}) +
                  " + " + paymentPhrase,
              "Contextual combination heuristic", "heuristic");
  if (debitClaim && recoveryClaim &&
      (paymentRequest || credentialRequest || contactRequest ||
       !candidates.empty()))
    addSignal(signals, "debit_recovery_lure",
              "Debit or charge claim paired with recovery language",
              "context_suspiciousness", "debit_recovery_lure", 70, 76,
              "An alleged debit or charge is paired with a refund or recovery "
              "claim. Verify transactions in the banking app independently.",
              firstPhrase(normalized, {"debited", "deducted", "charged"}) +
                  " + " +
                  firstPhrase(normalized, {"refund", "reverse the transaction",
                                           "recover your money"}),
              "Contextual combination heuristic", "heuristic");
  if (prizeClaim && (paymentRequest || kycRequest || credentialRequest))
    addSignal(signals, "prize_fee_lure",
              "Prize or reward claim paired with a sensitive request",
              "context_suspiciousness", "prize_fee_lure", 82, 83,
              "A prize or reward claim is paired with a payment, identity or "
              "credential request.",
              firstPhrase(normalized, {"won a prize", "claim your reward",
                                       "lottery", "lucky winner"}) +
                  " + requested action",
              "Contextual combination heuristic", "heuristic");
  if (awardContext) {
    int strength = 42;
    if (!awardSelectionPhrase.empty())
      strength += 8;
    if (monetaryAward)
      strength += 8;
    if (awardAction)
      strength += 14;
    if (!awardExpiryPhrase.empty())
      strength += 8;
    strength = std::min(82, strength);
    S evidence = "Award wording: " + awardPhrase;
    if (!awardSelectionPhrase.empty())
      evidence += "; selection wording: " + awardSelectionPhrase;
    if (monetaryAward)
      evidence += "; a currency amount is stated";
    if (awardAction)
      evidence += "; requested action: " + awardActionPhrase;
    if (!awardExpiryPhrase.empty())
      evidence += "; expiry wording: " + awardExpiryPhrase;
    if (awardReady)
      evidence += "; pending or ready reward wording";
    addSignal(signals, "contextual_reward_claim",
              "Unexpected reward or prize with claim context",
              "context_suspiciousness", "unexpected_reward_claim", strength,
              78,
              "A reward or prize mention is paired with selection, a stated "
              "amount, an action, or expiration pressure. This is a contextual "
              "heuristic, not confirmation of fraud.",
              evidence, "Contextual message pattern", "heuristic");
  }
  if (awardAction)
    addSignal(signals, "reward_claim_or_verification_action",
              "Request to claim or verify a reward",
              "requested_action_financial", "reward_claim_action", 62, 78,
              "The message asks the recipient to act on an unexpected reward "
              "or prize. The request is a risk cue, not proof of fraud.",
              awardActionPhrase, "Contextual message pattern", "heuristic");
  if (jobOrLoanClaim && upfrontFee)
    addSignal(signals, "job_loan_upfront_fee",
              "Job or loan claim paired with an upfront fee",
              "context_suspiciousness", "upfront_fee_lure", 78, 79,
              "A job, loan or investment claim is paired with an advance or "
              "processing fee request.",
              firstPhrase(normalized, {"job offer", "work from home",
                                       "loan approved", "instant loan",
                                       "guaranteed returns"}) +
                  " + " +
                  firstPhrase(normalized, {"registration fee",
                                           "processing fee", "advance fee",
                                           "upfront fee", "pay upfront"}),
              "Contextual combination heuristic", "heuristic");
  if (remoteAccess && financialContext &&
      (installRequest || credentialRequest || paymentRequest))
    addSignal(signals, "remote_access_financial_lure",
              "Remote-access tool paired with a financial interaction",
              "context_suspiciousness", "remote_access_lure", 88, 88,
              "Remote-access or screen-sharing software is mentioned beside "
              "a banking or payment request.",
              firstPhrase(normalized, {"anydesk", "teamviewer",
                                       "quick support", "rustdesk",
                                       "remote access", "screen sharing"}),
              "Contextual combination heuristic", "heuristic");

  const bool linkCueWithoutTarget =
      candidates.empty() &&
      anyPhrase(normalized, {"click here", "click the link", "tap the link",
                             "link below", "visit the link", "open this link",
                             "इस लिंक पर", "यहां क्लिक करें"});
  std::vector<LinkResult> linkResults;
  int analyzedLinks = 0;
  bool linksComplete = !linkCueWithoutTarget;
  for (const LinkCandidate &candidate : candidates) {
    LinkResult result =
        inspectUrl(candidate, claimed, signals);
    if (result.parsed)
      ++analyzedLinks;
    if (claimed && result.parsed &&
        officialDomain(result.host, *claimed))
      positiveEvidence.push_back(
          "Link host " + result.host +
          " matches a configured official-domain reference for " +
          claimed->name +
          "; domain matching does not verify the page or its download.");
    linksComplete = linksComplete && result.complete;
    linkResults.push_back(std::move(result));
  }
  if (awardAction && !candidates.empty() && !claimed) {
    S destinations;
    for (const LinkResult &link : linkResults) {
      if (link.host.empty())
        continue;
      if (!destinations.empty())
        destinations += ", ";
      destinations += link.host;
    }
    addSignal(signals, "unverified_reward_destination",
              "Unverified destination paired with a reward request",
              "link_destination", "unverified_reward_destination", 52, 72,
              "A reward claim or verification request directs the recipient "
              "to a destination whose ownership and reputation are not "
              "verified here. No reputation lookup was performed.",
              destinations.empty() ? "Reward action and link present"
                                   : destinations,
              "Contextual URL and message comparison", "unknown");
  }
  if (deliveryClaim && paymentRequest && !candidates.empty())
    addSignal(signals, "delivery_fee_link",
              "Delivery fee request paired with a link",
              "link_destination", "delivery_fee_link", 62, 76,
              "A parcel or delivery claim asks for payment through a link. "
              "The destination was not checked against a carrier registry.",
              linkResults.empty() ? "payment request + link"
                                  : linkResults.front().host,
              "Contextual link heuristic", "heuristic");
  if (linkCueWithoutTarget)
    notes.push_back("The message refers to a link, but no link destination "
                    "was present in the pasted text.");
  if (candidates.size() == 32)
    notes.push_back("URL extraction is limited to the first 32 link-like "
                    "values; additional URLs may not have been analyzed.");

  if (candidates.size() > 1 && riskyAction) {
    std::set<S> distinctHosts;
    for (const LinkResult &link : linkResults)
      if (!link.host.empty())
        distinctHosts.insert(link.host);
    if (distinctHosts.size() > 1)
      addSignal(signals, "multiple_destinations_with_action",
                "Multiple link domains accompany a requested action",
                "context_suspiciousness", "multiple_destination_action", 54,
                72,
                "The message includes links to multiple domains alongside a "
                "requested action; inspect each destination independently.",
                std::to_string(distinctHosts.size()) + " distinct domains",
                "Contextual link comparison", "heuristic");
  }

  J linkItems = J::array();
  for (size_t i = 0; i < linkResults.size(); ++i) {
    const LinkResult &link = linkResults[i];
    J item = {{"host", link.host},
              {"scheme", link.scheme},
              {"status", link.status},
              {"source", candidates[i].source},
              {"verification_status",
               link.parsed ? "structure_only_not_reputation_checked"
                           : "unknown"}};
    item["redirect_hosts"] = link.redirectHosts;
    linkItems.push_back(std::move(item));
  }
  J linkAssessment = {
      {"found", static_cast<int>(candidates.size())},
      {"analyzed", analyzedLinks},
      {"complete", linksComplete},
      {"items", linkItems},
      {"note",
       "Domains are extracted from pasted text. No URL reputation service, "
       "DNS lookup, redirect fetch, or link opening is performed."}};

  const std::map<S, int> dimensions = categoryScores(signals);
  const int weighted = weightedScore(dimensions);
  const InteractionResult interactions = interactionAssessment(dimensions);
  const int score = bounded(weighted + interactions.score);
  const S category = classificationFor(score);
  const int confidence = confidenceScore(signals, linksComplete);

  const int contentCoverage = clean.empty() ? 0 : 45;
  const int senderCoverage = sender.empty() ? 0 : 15;
  int linkCoverage = candidates.empty()
                         ? (linkCueWithoutTarget ? 0 : 15)
                         : static_cast<int>(
                               std::lround(25.0 * analyzedLinks /
                                           candidates.size()));
  if (linkCueWithoutTarget)
    linkCoverage = 0;
  const int organizationCoverage =
      claimed ? (candidates.empty() ? 10 : 15) : 5;
  const int completeness =
      bounded(contentCoverage + senderCoverage + linkCoverage +
              organizationCoverage);
  std::vector<S> missingEvidence;
  if (sender.empty())
    missingEvidence.push_back(
        "No sender ID or phone number was supplied; sender ownership cannot "
        "be compared.");
  else if (!senderOrganization)
    missingEvidence.push_back(
        "The sender value is not in the configured registry and remains "
        "unverified.");
  if (linkCueWithoutTarget)
    missingEvidence.push_back(
        "The text references a link that was not included, so its destination "
        "could not be inspected.");
  if (!linksComplete)
    missingEvidence.push_back(
        "One or more link-like values could not be parsed completely.");
  if (!claimed)
    missingEvidence.push_back(
        "No supported organization claim was identified for official-domain "
        "comparison.");
  if (candidates.empty() && !linkCueWithoutTarget)
    missingEvidence.push_back(
        "No link appeared in the pasted text; links omitted from the paste "
        "cannot be checked.");

  S advice;
  if (score >= HighRiskThreshold)
    advice =
        "Do not click links, reply, install software, share codes or pay. "
        "Contact the organization through its official app or a number you "
        "already trust.";
  else if (score >= CautionThreshold)
    advice =
        "Review the requested action carefully. Do not share OTPs, passwords "
        "or PINs; verify unexpected requests independently.";
  else
    advice =
        "No strong scam signals were found in this text. This is not proof "
        "that the sender or message is legitimate; verify unexpected requests "
        "independently.";

  J findings = J::array();
  for (const Signal &signal : signals)
    findings.push_back(signalJson(signal));
  J categoryScoresJson = J::object();
  for (const auto &dimension : dimensions)
    categoryScoresJson[dimension.first] = dimension.second;
  J weights = {{"link_destination", LinkWeight},
               {"sender_impersonation", SenderWeight},
               {"requested_action_financial", ActionWeight},
               {"urgency_pressure", UrgencyWeight},
               {"context_suspiciousness", ContextWeight}};
  J completenessComponents = {
      {"message_text", contentCoverage},
      {"sender_metadata", senderCoverage},
      {"link_analysis", linkCoverage},
      {"organization_domain_comparison", organizationCoverage}};
  J smsAssessment = {
      {"category_scores", categoryScoresJson},
      {"weights", weights},
      {"weighted_score", weighted},
      {"interaction_adjustment", interactions.score},
      {"interaction_reasons", interactions.reasons},
      {"summary", summaryFor(signals, score)},
      {"confidence",
       {{"score", confidence},
        {"label", confidenceLabel(confidence)},
        {"explanation",
         "Confidence describes how clearly the local rules matched the "
         "observed text and URL structure. It is not a probability that the "
         "message is malicious or safe."}}},
      {"completeness",
       {{"score", completeness},
        {"label", completeness >= 90 ? "Broad evidence coverage"
                                     : completeness >= 70 ? "Partial evidence"
                                                          : "Limited evidence"},
        {"components", completenessComponents},
        {"missing_evidence", missingEvidence}}},
      {"sender", senderAssessment},
      {"links", linkAssessment},
      {"positive_evidence", positiveEvidence},
      {"limitations",
       {"Sender display values are not authenticated.",
        "Only ICICI Bank is currently configured with official-domain "
        "references; no sender IDs or phone numbers are verified in the local "
        "registry.",
        "No external reputation or telecom sender registry is queried.",
        "HTTP redirects are not followed; only explicit URL query parameters "
        "are inspected."}}};

  return {{"type", "SMS"},
          {"target", "SMS message"},
          {"category", category},
          {"score", score},
          {"findings", findings},
          {"notes", notes},
          {"advice", advice},
          {"source", "CyberShield local contextual SMS analysis"},
          {"sms_assessment", smsAssessment}};
}
