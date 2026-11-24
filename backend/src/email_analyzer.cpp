#include "email_analyzer.h"

#include "download_source_registry.h"
#include "dsa.h"
#include "email_risk_config.h"
#include "sms_sender_registry.h"
#include "website_inspector.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <regex>
#include <sstream>

namespace {
const S UrgencyCategory = "urgency_manipulation";
const S LinkCategory = "link_destination";
const S SenderCategory = "sender_authenticity";
const S FinancialCategory = "financial_sensitive_action";
const S ContentCategory = "content_suspiciousness";
constexpr size_t MaxEmailLinks = 32;

struct EmailSignal {
  S id;
  S name;
  S category;
  S family;
  S severity;
  S explanation;
  S evidence;
  S evidenceStatus;
  int strength = 0;
  int occurrences = 1;
};

struct EmailLink {
  S destination;
  S visibleText;
  S source;
};

struct LinkExtraction {
  std::vector<EmailLink> links;
  Args issues;
  bool complete = true;
};

struct HeaderFields {
  S from;
  S replyTo;
  S authenticationResults;
  bool malformed = false;
};

struct ParsedEmailLink {
  EmailLink input;
  S host;
  S status;
};

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

S wordsOnly(const S &value) {
  S output;
  for (unsigned char c : lowerAscii(value)) {
    if (c >= 128 || std::isalnum(c))
      output += static_cast<char>(c);
    else if (!output.empty() && output.back() != ' ')
      output += ' ';
  }
  while (!output.empty() && output.back() == ' ')
    output.pop_back();
  return output;
}

bool hasPhrase(const S &normalizedText, const S &phrase) {
  const S normalizedPhrase = wordsOnly(phrase);
  return !normalizedPhrase.empty() &&
         (" " + normalizedText + " ").find(" " + normalizedPhrase + " ") !=
             S::npos;
}

S firstPhrase(const S &normalizedText, const Args &phrases) {
  for (const S &phrase : phrases)
    if (hasPhrase(normalizedText, phrase))
      return phrase;
  return {};
}

bool hasCurrencyAmount(const S &text) {
  static const std::regex amount(
      R"((₹|rs\.?|inr|usd|\$)\s*[0-9][0-9,]*(\.[0-9]{1,2})?)",
      std::regex::icase);
  return std::regex_search(text, amount);
}

int phraseCount(const S &normalizedText, const S &phrase) {
  const S normalizedPhrase = wordsOnly(phrase);
  if (normalizedPhrase.empty())
    return 0;
  const S padded = " " + normalizedText + " ";
  const S needle = " " + normalizedPhrase + " ";
  int count = 0;
  for (size_t position = padded.find(needle); position != S::npos;
       position = padded.find(needle, position + needle.size()))
    ++count;
  return count;
}

S normalizeMessageText(const S &message) {
  S output;
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
      if (!output.empty() && output.back() != ' ')
        output += ' ';
      i += starts("\xC2\xA0", 2) ? 2 : 3;
      continue;
    }
    const unsigned char c = static_cast<unsigned char>(message[i++]);
    if (c < 0x20 || c == 0x7f) {
      if (!output.empty() && output.back() != ' ')
        output += ' ';
    } else {
      output += static_cast<char>(c);
    }
  }
  return lowerAscii(output);
}

void replaceAll(S &value, const S &from, const S &to) {
  if (from.empty())
    return;
  for (size_t position = value.find(from); position != S::npos;
       position = value.find(from, position + to.size()))
    value.replace(position, from.size(), to);
}

S decodeHtmlEntities(S value) {
  replaceAll(value, "&amp;", "&");
  replaceAll(value, "&quot;", "\"");
  replaceAll(value, "&#39;", "'");
  replaceAll(value, "&apos;", "'");
  replaceAll(value, "&lt;", "<");
  replaceAll(value, "&gt;", ">");
  replaceAll(value, "&#x2f;", "/");
  replaceAll(value, "&#X2F;", "/");
  return value;
}

S visibleHtmlText(S value) {
  static const std::regex hiddenElements(
      R"html(<(script|style)\b[^>]*>[\s\S]*?</\1\s*>)html",
      std::regex::icase);
  static const std::regex tags(R"html(<[^>]*>)html", std::regex::icase);
  value = std::regex_replace(value, hiddenElements, " ");
  value = std::regex_replace(value, tags, " ");
  return decodeHtmlEntities(value);
}

void blankRange(S &text, size_t start, size_t end) {
  end = std::min(end, text.size());
  for (size_t i = start; i < end; ++i)
    if (text[i] != '\r' && text[i] != '\n')
      text[i] = ' ';
}

bool htmlAttribute(const S &tag, const S &attribute, S &value) {
  const S folded = lowerAscii(tag);
  size_t position = 0;
  while ((position = folded.find(attribute, position)) != S::npos) {
    const bool leftBoundary =
        position == 0 ||
        (!std::isalnum(static_cast<unsigned char>(folded[position - 1])) &&
         folded[position - 1] != '-' && folded[position - 1] != '_');
    size_t cursor = position + attribute.size();
    const bool rightBoundary =
        cursor == folded.size() ||
        !std::isalnum(static_cast<unsigned char>(folded[cursor]));
    if (!leftBoundary || !rightBoundary) {
      position = cursor;
      continue;
    }
    while (cursor < folded.size() &&
           std::isspace(static_cast<unsigned char>(folded[cursor])))
      ++cursor;
    if (cursor >= folded.size() || folded[cursor] != '=') {
      position = cursor;
      continue;
    }
    ++cursor;
    while (cursor < tag.size() &&
           std::isspace(static_cast<unsigned char>(tag[cursor])))
      ++cursor;
    if (cursor >= tag.size())
      return false;
    const char quote = tag[cursor] == '"' || tag[cursor] == '\''
                           ? tag[cursor++]
                           : '\0';
    const size_t start = cursor;
    if (quote) {
      const auto end = tag.find(quote, start);
      if (end == S::npos)
        return false;
      value = tag.substr(start, end - start);
      return true;
    }
    while (cursor < tag.size() &&
           !std::isspace(static_cast<unsigned char>(tag[cursor])) &&
           tag[cursor] != '>')
      ++cursor;
    if (cursor == start)
      return false;
    value = tag.substr(start, cursor - start);
    return true;
  }
  return false;
}

void addExtractionIssue(LinkExtraction &result, const S &issue) {
  result.complete = false;
  if (std::find(result.issues.begin(), result.issues.end(), issue) ==
      result.issues.end())
    result.issues.push_back(issue);
}

void appendEmailLink(LinkExtraction &result, S destination, S visibleText,
                     const S &source) {
  destination = trim(decodeHtmlEntities(destination));
  if (destination.size() >= 2 && destination.front() == '<' &&
      destination.back() == '>')
    destination = destination.substr(1, destination.size() - 2);
  destination = trimLink(destination);
  visibleText = trim(visibleHtmlText(visibleText));
  if (destination.empty()) {
    addExtractionIssue(result, "A link element had no readable destination.");
    return;
  }
  const S key = lowerAscii(destination);
  for (const auto &link : result.links)
    if (lowerAscii(link.destination) == key)
      return;
  if (result.links.size() >= MaxEmailLinks) {
    addExtractionIssue(
        result, "The email contains more than 32 links; remaining links were "
                "not analyzed.");
    return;
  }
  result.links.push_back({destination, visibleText, source});
}

LinkExtraction extractEmailLinks(const S &body) {
  LinkExtraction result;
  S remaining = body;
  const S foldedBody = lowerAscii(body);
  static const std::regex anchorStart(R"html(<a\b[^>]*>)html",
                                      std::regex::icase);
  for (std::sregex_iterator it(body.begin(), body.end(), anchorStart), end;
       it != end; ++it) {
    const size_t start = static_cast<size_t>(it->position());
    const size_t tagEnd = start + static_cast<size_t>(it->length());
    const S tag = it->str();
    S href;
    const bool hasHref = htmlAttribute(tag, "href", href);
    const size_t closingStart = foldedBody.find("</a", tagEnd);
    if (closingStart == S::npos) {
      if (hasHref) {
        appendEmailLink(result, href, {}, "html");
        addExtractionIssue(result,
                           "An HTML link was missing its closing anchor tag.");
        blankRange(remaining, start, tagEnd);
      }
      continue;
    }
    const size_t closingEndStart = body.find('>', closingStart);
    const size_t rangeEnd = closingEndStart == S::npos
                                ? body.size()
                                : closingEndStart + 1;
    if (hasHref) {
      const S label = body.substr(tagEnd, closingStart - tagEnd);
      appendEmailLink(result, href, label, "html");
      if (closingEndStart == S::npos)
        addExtractionIssue(result,
                           "An HTML link had an incomplete closing tag.");
      blankRange(remaining, start, rangeEnd);
    } else if (lowerAscii(tag).find("href") != S::npos) {
      addExtractionIssue(result,
                         "An HTML link destination could not be extracted.");
      blankRange(remaining, start, rangeEnd);
    }
  }

  size_t searchFrom = 0;
  while (true) {
    const size_t open = remaining.find('[', searchFrom);
    if (open == S::npos)
      break;
    const size_t labelEnd = remaining.find(']', open + 1);
    if (labelEnd == S::npos) {
      const S tail = lowerAscii(remaining.substr(open));
      if (tail.find("http://") != S::npos ||
          tail.find("https://") != S::npos ||
          tail.find("www.") != S::npos)
        addExtractionIssue(result,
                           "A Markdown-style link label was incomplete.");
      break;
    }
    if (labelEnd + 1 >= remaining.size() ||
        remaining[labelEnd + 1] != '(') {
      searchFrom = labelEnd + 1;
      continue;
    }
    size_t close = S::npos;
    int depth = 1;
    for (size_t cursor = labelEnd + 2; cursor < remaining.size(); ++cursor) {
      if (remaining[cursor] == '(')
        ++depth;
      else if (remaining[cursor] == ')' && --depth == 0) {
        close = cursor;
        break;
      }
    }
    const size_t destinationStart = labelEnd + 2;
    size_t contentEnd = close == S::npos ? remaining.size() : close;
    while (contentEnd > destinationStart &&
           std::isspace(static_cast<unsigned char>(remaining[contentEnd - 1])))
      --contentEnd;
    size_t destinationEnd = destinationStart;
    while (destinationEnd < contentEnd &&
           !std::isspace(static_cast<unsigned char>(remaining[destinationEnd])))
      ++destinationEnd;
    S destination =
        remaining.substr(destinationStart, destinationEnd - destinationStart);
    if (destination.size() >= 2 && destination.front() == '<' &&
        destination.back() == '>')
      destination = destination.substr(1, destination.size() - 2);
    appendEmailLink(result, destination,
                    remaining.substr(open + 1, labelEnd - open - 1),
                    "markdown");
    if (close == S::npos) {
      addExtractionIssue(result,
                         "A Markdown link was missing its closing parenthesis.");
      blankRange(remaining, open, remaining.size());
      break;
    }
    blankRange(remaining, open, close + 1);
    searchFrom = close + 1;
  }

  static const std::regex urlToken(
      R"url(([a-z][a-z0-9+.-]*://[^\s<>"']+|www\.[^\s<>"']+))url",
      std::regex::icase);
  for (std::sregex_iterator it(remaining.begin(), remaining.end(), urlToken),
       end;
       it != end; ++it)
    appendEmailLink(result, trimLink(it->str()), {}, "plain_text");
  return result;
}

HeaderFields parseEmailHeaders(const S &rawHeaders) {
  HeaderFields result;
  std::istringstream input(rawHeaders);
  S line, currentName, currentValue;
  const auto commit = [&]() {
    if (currentName == "from" && result.from.empty())
      result.from = trim(currentValue);
    else if (currentName == "reply-to" && result.replyTo.empty())
      result.replyTo = trim(currentValue);
    else if (currentName == "authentication-results") {
      if (!result.authenticationResults.empty())
        result.authenticationResults += " ";
      result.authenticationResults += trim(currentValue);
    }
  };
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
      if (currentName.empty())
        result.malformed = true;
      else
        currentValue += " " + trim(line);
      continue;
    }
    commit();
    currentName.clear();
    currentValue.clear();
    const size_t colon = line.find(':');
    if (colon == S::npos) {
      if (!trim(line).empty())
        result.malformed = true;
      continue;
    }
    currentName = lowerAscii(trim(line.substr(0, colon)));
    currentValue = trim(line.substr(colon + 1));
  }
  commit();
  return result;
}

S mailbox(S raw) {
  const auto start = raw.rfind('<');
  const auto end = raw.find('>', start);
  if (start != S::npos && end != S::npos)
    raw = raw.substr(start + 1, end - start - 1);
  raw = trim(raw);
  static const std::regex address(
      R"([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)");
  if (!std::regex_match(raw, address))
    throw Problem(400, "Enter a valid sender email address.");
  return lowerAscii(raw);
}

S emailDomain(const S &address) {
  const size_t at = address.rfind('@');
  return at == S::npos ? S() : lowerAscii(address.substr(at + 1));
}

bool domainOrSubdomain(const S &host, const S &domain) {
  return host == domain ||
         (host.size() > domain.size() &&
          host.compare(host.size() - domain.size(), domain.size(), domain) ==
              0 &&
          host[host.size() - domain.size() - 1] == '.');
}

bool matchesOfficialDomain(const S &host,
                           const SmsOrganization &organization) {
  for (const S &domain : organization.officialDomains)
    if (domainOrSubdomain(host, lowerAscii(domain)))
      return true;
  return false;
}

const SmsOrganization *findClaimedOrganization(const S &message) {
  const S normalized = wordsOnly(message);
  for (const SmsOrganization &organization : smsOrganizationRegistry()) {
    if (hasPhrase(normalized, organization.name))
      return &organization;
    for (const S &alias : organization.aliases)
      if (hasPhrase(normalized, alias))
        return &organization;
  }
  return nullptr;
}

const SmsOrganization *findOrganizationByDomain(const S &domain) {
  for (const SmsOrganization &organization : smsOrganizationRegistry())
    if (matchesOfficialDomain(domain, organization))
      return &organization;
  return nullptr;
}

bool consumerMailbox(const S &domain) {
  static const Args domains = {
      "gmail.com",      "googlemail.com", "outlook.com", "hotmail.com",
      "live.com",       "yahoo.com",      "yahoo.co.in", "icloud.com",
      "me.com",         "aol.com",        "proton.me",   "protonmail.com"};
  return linearSearch(domains, lowerAscii(domain));
}

bool sameDisplayedDomain(const S &first, const S &second) {
  const auto normalize = [](S host) {
    host = lowerAscii(host);
    if (host.rfind("www.", 0) == 0)
      host.erase(0, 4);
    while (!host.empty() && host.back() == '.')
      host.pop_back();
    return host;
  };
  const S a = normalize(first);
  const S b = normalize(second);
  return a == b || domainOrSubdomain(a, b) || domainOrSubdomain(b, a);
}

S rawUrlHost(const S &rawUrl) {
  size_t start = rawUrl.find("://");
  if (start != S::npos)
    start += 3;
  else if (rawUrl.rfind("//", 0) == 0)
    start = 2;
  else
    start = 0;
  const size_t end = rawUrl.find_first_of("/?#", start);
  S authority = rawUrl.substr(start, end == S::npos ? S::npos : end - start);
  const size_t at = authority.rfind('@');
  if (at != S::npos)
    authority.erase(0, at + 1);
  if (!authority.empty() && authority.front() == '[') {
    const size_t closing = authority.find(']');
    return closing == S::npos ? authority : authority.substr(0, closing + 1);
  }
  const size_t port = authority.rfind(':');
  if (port != S::npos)
    authority.resize(port);
  return authority;
}

S extractVisibleDomain(const S &label) {
  S value = trim(visibleHtmlText(label));
  value = trimLink(value);
  if (value.empty() || value.find_first_of(" \t\r\n") != S::npos)
    return {};
  const S folded = lowerAscii(value);
  if (folded.rfind("https://", 0) != 0 &&
      folded.rfind("http://", 0) != 0 &&
      folded.rfind("//", 0) != 0 &&
      folded.rfind("www.", 0) != 0 &&
      folded.find('.') == S::npos)
    return {};
  if (folded.rfind("https://", 0) != 0 &&
      folded.rfind("http://", 0) != 0 &&
      folded.rfind("//", 0) != 0)
    value = "https://" + value;
  website_inspector::ParsedUrl parsed;
  S error;
  if (!website_inspector::parseUrl(value, parsed, error))
    return {};
  return parsed.host;
}

void addSignal(std::vector<EmailSignal> &signals, const S &id, const S &name,
               const S &category, const S &family, int strength,
               const S &explanation, const S &evidence,
               const S &evidenceStatus = "heuristic", int occurrences = 1) {
  strength = std::max(0, std::min(100, strength));
  if (!strength)
    return;
  for (EmailSignal &signal : signals) {
    if (signal.id == id && signal.category == category &&
        signal.evidence == evidence) {
      signal.strength = std::max(signal.strength, strength);
      signal.occurrences += std::max(1, occurrences);
      return;
    }
  }
  const S severity = strength >= 85   ? "critical"
                     : strength >= 65 ? "high"
                     : strength >= 40 ? "moderate"
                     : strength >= 20 ? "low"
                                      : "observation";
  signals.push_back({id, name, category, family, severity, explanation,
                     evidence, evidenceStatus, strength,
                     std::max(1, occurrences)});
}

int categoryScore(const std::vector<EmailSignal> &signals,
                  const S &category) {
  std::map<S, std::vector<const EmailSignal *>> families;
  for (const EmailSignal &signal : signals)
    if (signal.category == category)
      families[signal.family].push_back(&signal);
  double remaining = 1.0;
  for (auto &family : families) {
    auto &items = family.second;
    std::sort(items.begin(), items.end(),
              [](const EmailSignal *left, const EmailSignal *right) {
                return left->strength > right->strength;
              });
    int familyStrength = items.front()->strength;
    for (size_t i = 1; i < items.size(); ++i)
      familyStrength += std::min(5, items[i]->strength / 10);
    familyStrength = std::min(100, familyStrength);
    remaining *= (100.0 - familyStrength) / 100.0;
  }
  return std::max(0, std::min(100, static_cast<int>(
                                        std::lround((1.0 - remaining) *
                                                    100.0))));
}

J categoryScores(const std::vector<EmailSignal> &signals) {
  return {{UrgencyCategory, categoryScore(signals, UrgencyCategory)},
          {LinkCategory, categoryScore(signals, LinkCategory)},
          {SenderCategory, categoryScore(signals, SenderCategory)},
          {FinancialCategory, categoryScore(signals, FinancialCategory)},
          {ContentCategory, categoryScore(signals, ContentCategory)}};
}

int weightedScore(const J &scores) {
  const int weighted =
      scores.value(UrgencyCategory, 0) * email_risk::config::UrgencyWeight +
      scores.value(LinkCategory, 0) * email_risk::config::LinkWeight +
      scores.value(SenderCategory, 0) * email_risk::config::SenderWeight +
      scores.value(FinancialCategory, 0) *
          email_risk::config::FinancialWeight +
      scores.value(ContentCategory, 0) * email_risk::config::ContentWeight;
  return (weighted + 50) / 100;
}

int interactionBonus(const J &scores, Args &explanations) {
  const int urgency = scores.value(UrgencyCategory, 0);
  const int links = scores.value(LinkCategory, 0);
  const int sender = scores.value(SenderCategory, 0);
  const int financial = scores.value(FinancialCategory, 0);
  const int content = scores.value(ContentCategory, 0);
  int numerator = 0;
  const auto combine = [&](int left, int right, int weight,
                           const S &explanation) {
    if (left < 35 || right < 35)
      return;
    numerator += std::min(left, right) * weight;
    explanations.push_back(explanation);
  };
  combine(urgency, financial,
          email_risk::config::UrgencyFinancialInteractionWeight,
          "Urgency corroborates a sensitive or actionable request.");
  combine(links, sender, email_risk::config::LinkSenderInteractionWeight,
          "Link-destination and sender-authenticity concerns corroborate "
          "each other.");
  combine(links, financial,
          email_risk::config::LinkFinancialInteractionWeight,
          "A sensitive or actionable request is paired with link risk.");
  combine(urgency, links,
          email_risk::config::UrgencyLinkInteractionWeight,
          "Pressure language is paired with a link that needs review.");
  combine(urgency, content,
          email_risk::config::UrgencyContentInteractionWeight,
          "Pressure language corroborates suspicious message context.");
  combine(financial, content,
          email_risk::config::FinancialContentInteractionWeight,
          "An actionable request corroborates suspicious message context.");
  combine(sender, financial,
          email_risk::config::SenderFinancialInteractionWeight,
          "Sender uncertainty accompanies a sensitive or actionable request.");
  combine(sender, content,
          email_risk::config::SenderContentInteractionWeight,
          "Sender uncertainty accompanies suspicious message context.");
  combine(links, content,
          email_risk::config::LinkContentInteractionWeight,
          "Link risk corroborates suspicious message context.");
  return std::min(email_risk::config::MaximumInteractionBonus,
                  (numerator + 50) / 100);
}

S authenticationResult(const S &results, const S &method) {
  const std::regex pattern("\\b" + method +
                               "\\s*=\\s*(pass|fail|softfail|neutral|none|"
                               "temperror|permerror)\\b",
                           std::regex::icase);
  std::smatch match;
  return std::regex_search(results, match, pattern)
             ? lowerAscii(match[1].str())
             : S();
}

bool isNegatedRequest(const S &text, const S &request) {
  size_t position = text.find(request);
  bool found = false;
  while (position != S::npos) {
    found = true;
    const size_t start = position > 36 ? position - 36 : 0;
    const S before = wordsOnly(text.substr(start, position - start));
    const auto endsWith = [&](const S &suffix) {
      return before == suffix ||
             (before.size() > suffix.size() &&
              before.compare(before.size() - suffix.size(), suffix.size(),
                             suffix) == 0 &&
              before[before.size() - suffix.size() - 1] == ' ');
    };
    const bool negated =
        hasPhrase(before, "never ask you to") ||
        hasPhrase(before, "do not ask you to") ||
        hasPhrase(before, "do not share") ||
        hasPhrase(before, "never share") ||
        hasPhrase(before, "don't share") ||
        endsWith("do not") || endsWith("never") || endsWith("don t") ||
        endsWith("not to");
    if (!negated)
      return false;
    position = text.find(request, position + request.size());
  }
  return found;
}

S riskCategory(int score) {
  if (score >= email_risk::config::HighRiskThreshold)
    return "High risk";
  if (score >= email_risk::config::SuspiciousThreshold)
    return "Suspicious";
  if (score >= email_risk::config::CautionThreshold)
    return "Caution";
  return "Low Risk";
}

S categoryLabel(const S &category) {
  if (category == UrgencyCategory)
    return "Urgency and manipulation";
  if (category == LinkCategory)
    return "Link and destination risk";
  if (category == SenderCategory)
    return "Sender authenticity";
  if (category == FinancialCategory)
    return "Financial and sensitive actions";
  if (category == ContentCategory)
    return "Content suspiciousness";
  return category;
}

S confidenceLabel(int confidence) {
  if (confidence >= 90)
    return "Good evidence coverage";
  if (confidence >= 60)
    return "Partial evidence";
  return "Limited evidence";
}

S conciseSummary(const J &scores, const S &category,
                 const std::vector<EmailSignal> &signals,
                 const Args &interactionExplanations, int adjustment) {
  if (signals.empty())
    return "No configured high-risk indicators were detected in the supplied "
           "text. This does not verify the sender or prove the message is safe.";
  std::vector<std::pair<int, S>> ranked;
  for (const S &key : Args{UrgencyCategory, LinkCategory, SenderCategory,
                           FinancialCategory, ContentCategory}) {
    const int value = scores.value(key, 0);
    if (value > 0)
      ranked.push_back({value, categoryLabel(key)});
  }
  std::sort(ranked.begin(), ranked.end(),
            [](const auto &left, const auto &right) {
              return left.first > right.first;
            });
  S summary = category + " based on ";
  const size_t count = std::min<size_t>(3, ranked.size());
  for (size_t i = 0; i < count; ++i) {
    if (i)
      summary += i + 1 == count ? " and " : ", ";
    summary += lowerAscii(ranked[i].second);
  }
  summary += ". The score reflects only evidence available in the pasted "
             "message.";
  if (adjustment > 0) {
    summary += " Independent evidence combinations add " +
               std::to_string(adjustment) + " points";
    if (adjustment == email_risk::config::MaximumInteractionBonus)
      summary += " (the configured combination cap)";
    summary += ".";
    for (const S &explanation : interactionExplanations)
      summary += " " + explanation;
  }
  return summary;
}
} // namespace

J analyzeEmail(const J &input) {
  const S body = field(input, "content", 20000);
  S sender = field(input, "sender", 254, false);
  const S subject = field(input, "subject", 300, false);
  const S rawHeaders = field(input, "headers", 8192, false);

  HeaderFields headers = parseEmailHeaders(rawHeaders);
  if (!sender.empty())
    sender = mailbox(sender);
  else if (!headers.from.empty()) {
    try {
      sender = mailbox(headers.from);
    } catch (const Problem &) {
      headers.malformed = true;
    }
  }
  const S visibleBody = visibleHtmlText(body);
  const S normalizedMessage =
      normalizeMessageText(visibleBody + " " + subject);
  const S words = wordsOnly(normalizedMessage);
  const S senderDomain = emailDomain(sender);

  LinkExtraction extraction = extractEmailLinks(body);
  const bool hasLink = !extraction.links.empty();
  const Args urgencyTerms = {
      "urgent", "immediately", "right now", "within 24 hours",
      "final notice", "final warning", "last chance", "action required",
      "deadline", "expires today", "expires soon", "ends today",
      "act immediately", "claim before",
      "account suspended", "account restricted", "account blocked",
      "account will be closed", "legal action", "access will expire",
      "respond today", "act now", "turant", "abhi", "aaj hi",
      "account band hoga", "खाता बंद", "खाता ब्लॉक", "तुरंत करें"};
  const Args threatTerms = {
      "account suspended", "account restricted", "account blocked",
      "account will be closed", "legal action", "access will be disabled",
      "service will be terminated", "final warning", "last chance",
      "lose eligibility", "lose your eligibility", "lose the reward",
      "lose your reward", "forfeit your prize", "forfeit your reward",
      "reward will be cancelled", "prize will be cancelled",
      "reward will be canceled", "prize will be canceled",
      "eligibility will expire"};
  const Args credentialTerms = {
      "send your password", "enter your password", "share your password",
      "confirm your password", "verify your password",
      "enter your login credentials", "send your otp", "send us your otp",
      "share your otp", "provide your otp", "reply with your otp",
      "share the code", "send the verification code",
      "provide your verification code", "confirm your login",
      "password bhejo", "password batao", "otp bhejo", "otp batao",
      "otp share karo", "otp share karein", "otp send karo",
      "apna otp bhejo", "otp bata do", "password share karo",
      "अपना ओटीपी भेजें", "ओटीपी साझा करें", "ओटीपी भेजें",
      "ओटीपी बताएं", "पासवर्ड बताएं", "पासवर्ड भेजें"};
  const Args sensitiveDataTerms = {
      "confirm your details", "verify your identity",
      "verify your personal details", "verify your details",
      "provide your personal information", "upload your id",
      "update your bank details", "confirm your bank details",
      "update your payment method", "change your bank account",
      "enter your card details", "provide your account number",
      "provide your personal details", "confirm your personal details"};
  const Args paymentActionTerms = {
      "pay now", "please pay", "pay the fee", "pay the invoice",
      "make a payment", "submit payment", "payment is due",
      "payment is overdue", "settle the balance", "send money",
      "transfer money", "wire transfer", "pay rs", "pay usd",
      "update your payment method", "change your bank account",
      "update your bank details", "confirm your bank details",
      "paise bhejo", "paisa transfer karo", "payment karo",
      "पैसे भेजें", "भुगतान करें", "राशि जमा करें"};
  const Args renewalTerms = {
      "subscription renewed", "automatically renewed",
      "subscription renewal", "annual plan", "renewal charge",
      "renewal payment"};
  const Args chargeTerms = {
      "debited", "charged", "charge", "payment receipt",
      "payment of", "amount deducted", "transaction amount",
      "unauthorized charge", "unrecognized charge"};
  const Args unauthorizedTerms = {
      "did not authorize", "didn't authorize", "unauthorized",
      "unrecognized charge", "do not recognize", "don't recognize",
      "not my purchase", "not authorized by me"};
  const Args recoveryActionTerms = {
      "cancellation request", "submit a cancellation",
      "request a refund", "refund request", "claim a refund",
      "cancel subscription", "dispute this charge", "reverse this charge",
      "reverse the payment", "unsubscribe"};
  const Args kycTerms = {
      "update your kyc", "complete kyc", "kyc update",
      "verify your account", "reactivate your account",
      "confirm your details", "verify your identity",
      "kyc update karo", "kyc abhi update",
      "खाता फिर से चालू", "केवाईसी अपडेट करें"};
  const Args awardTerms = {"prize", "reward", "giveaway", "lottery",
                           "winnings", "winner", "jackpot", "cash prize"};
  const Args winnerTerms = {
      "you won a prize", "you have won a prize", "you won the prize",
      "winner selection", "selected as a winner", "chosen as a winner",
      "you are a winner", "you are the winner", "lucky winner",
      "lottery winner", "selected for a prize", "we selected you"};
  const Args awardClaimTerms = {
      "claim your prize", "claim a prize", "claim the prize", "claim prize",
      "prize claim", "claim your reward", "claim the reward", "claim reward",
      "reward claim", "claim your winnings", "redeem your prize",
      "redeem your reward", "collect your prize", "collect your reward",
      "receive your prize", "receive your reward", "claim your gift"};
  const Args awardVerificationTerms = {
      "verify to claim", "verify your prize", "verify your reward",
      "verification required to claim", "complete verification to claim",
      "confirm your identity to claim", "verify your identity to claim",
      "verify your details to claim", "confirm your details to claim",
      "complete verification to receive"};
  const Args awardDenialTerms = {
      "you did not win", "you didn't win", "not a winner",
      "not selected as a winner", "no prize was won"};

  const S urgencyPhrase = firstPhrase(words, urgencyTerms);
  const S threatPhrase = firstPhrase(words, threatTerms);
  const bool urgency = !urgencyPhrase.empty();
  const bool explicitThreat = !threatPhrase.empty();
  const S awardPhrase = firstPhrase(words, awardTerms);
  const S winnerPhrase = firstPhrase(words, winnerTerms);
  const S awardClaimPhrase = firstPhrase(words, awardClaimTerms);
  const S awardVerificationPhrase =
      firstPhrase(words, awardVerificationTerms);
  const bool awardDenied = !firstPhrase(words, awardDenialTerms).empty();
  const bool monetaryAward = hasCurrencyAmount(normalizedMessage);
  const bool winnerClaimed =
      !winnerPhrase.empty() && !awardDenied &&
      !isNegatedRequest(normalizedMessage, winnerPhrase);
  const bool awardClaimRequest =
      !awardClaimPhrase.empty() &&
      !isNegatedRequest(normalizedMessage, awardClaimPhrase);
  const bool awardVerificationRequest =
      !awardVerificationPhrase.empty() &&
      !isNegatedRequest(normalizedMessage, awardVerificationPhrase);
  const bool awardContext =
      !awardPhrase.empty() && !awardDenied &&
      (winnerClaimed || awardClaimRequest || awardVerificationRequest ||
       monetaryAward);
  const bool prizeClaim = awardContext && awardClaimRequest;
  const bool prizeVerification = awardContext && awardVerificationRequest;
  const S credentialPhrase = firstPhrase(words, credentialTerms);
  const bool credentialRequest =
      !credentialPhrase.empty() &&
      !isNegatedRequest(normalizedMessage, credentialPhrase);
  const S sensitiveDataPhrase = firstPhrase(words, sensitiveDataTerms);
  const bool sensitiveDataRequest =
      !sensitiveDataPhrase.empty() &&
      !isNegatedRequest(normalizedMessage, sensitiveDataPhrase);
  const S paymentActionPhrase = firstPhrase(words, paymentActionTerms);
  const bool paymentAction =
      !paymentActionPhrase.empty() &&
      !isNegatedRequest(normalizedMessage, paymentActionPhrase);
  const bool renewalClaim = !firstPhrase(words, renewalTerms).empty();
  const bool chargeClaim = !firstPhrase(words, chargeTerms).empty();
  const bool unauthorizedCharge = !firstPhrase(words, unauthorizedTerms).empty();
  const bool recoveryAction = !firstPhrase(words, recoveryActionTerms).empty();
  const S kycPhrase = firstPhrase(words, kycTerms);
  const bool kycRequest =
      !kycPhrase.empty() && !isNegatedRequest(normalizedMessage, kycPhrase);
  const bool sensitiveRequest =
      credentialRequest || sensitiveDataRequest || kycRequest;
  const bool actionableAward = prizeClaim || prizeVerification;
  const bool financialAction =
      paymentAction || sensitiveRequest ||
      (renewalClaim && chargeClaim && recoveryAction &&
       (urgency || hasLink));
  const bool serviceClaim =
      !firstPhrase(words, {"parcel", "delivery", "shipment", "tracking",
                           "redelivery", "delivery failed"})
           .empty();

  std::vector<EmailSignal> signals;
  J positiveEvidence = J::array();
  Args limitations;

  if (urgency) {
    const int occurrences = std::min(phraseCount(words, urgencyPhrase), 6);
    const bool pairedWithAction =
        financialAction || sensitiveRequest || actionableAward || hasLink;
    const int strength =
        explicitThreat ? (pairedWithAction ? 82 : 55)
                       : (pairedWithAction ? 58 : 22);
    addSignal(signals, "urgency_pressure", "Urgency or pressure language",
              UrgencyCategory, "pressure_language", strength,
              explicitThreat
                  ? "The message threatens a loss of account access, "
                    "eligibility, or a promised benefit."
                  : financialAction || sensitiveRequest || actionableAward ||
                            hasLink
                        ? "Pressure language appears with an actionable "
                          "request or link."
                        : "Pressure wording appears without a strong risky "
                          "request; urgency alone is weak evidence.",
              "Matched wording: " + urgencyPhrase, "heuristic", occurrences);
  }

  if (awardContext) {
    int strength = 38;
    if (winnerClaimed)
      strength += 12;
    if (prizeClaim || prizeVerification)
      strength += 14;
    if (monetaryAward)
      strength += 8;
    if (explicitThreat)
      strength += 8;
    strength = std::min(82, strength);
    S evidence = "Award wording: " + awardPhrase;
    if (winnerClaimed)
      evidence += "; winner-selection wording: " + winnerPhrase;
    if (prizeClaim)
      evidence += "; claim wording: " + awardClaimPhrase;
    if (prizeVerification)
      evidence += "; verification wording: " + awardVerificationPhrase;
    if (monetaryAward)
      evidence += "; a monetary amount is stated";
    addSignal(signals, "contextual_prize_reward_claim",
              "Contextual prize or reward claim", ContentCategory,
              "prize_reward_lure", strength,
              "Unexpected award language is paired with a winner, claim, "
              "verification, or monetary cue. This is a heuristic lure "
              "indicator, not confirmation of fraud.",
              evidence);
  }

  if (credentialRequest) {
    addSignal(signals, "credential_request", "Credential or code request",
              FinancialCategory, "credential_request", 100,
              "The message asks the recipient to provide a password, OTP, or "
              "verification code. A notification that merely states an OTP is "
              "not treated as a request.",
              "Matched wording: " + credentialPhrase);
  }
  if (sensitiveDataRequest && !credentialRequest) {
    addSignal(signals, "sensitive_data_request", "Sensitive information request",
              FinancialCategory, "sensitive_information_request", 78,
              "The message asks for personal, identity, bank, or payment "
              "details.",
              "Matched wording: " + sensitiveDataPhrase);
  }
  if (kycRequest && !sensitiveDataRequest) {
    addSignal(signals, "kyc_request", "Account or KYC action request",
              FinancialCategory, "account_action_request", 68,
              "The message asks the recipient to verify, reactivate, or update "
              "an account or KYC details.",
              "Matched wording: " + kycPhrase);
  }
  if (prizeClaim) {
    addSignal(signals, "prize_claim_action", "Prize or reward claim request",
              FinancialCategory, "benefit_claim_request", 58,
              "The message asks the recipient to take an action to claim an "
              "unexpected prize or reward. A claim request is a risk cue, not "
              "proof that the offer is fraudulent.",
              "Matched wording: " + awardClaimPhrase);
  }
  if (prizeVerification && !sensitiveRequest) {
    addSignal(signals, "prize_verification_request",
              "Verification requested to release a prize or reward",
              FinancialCategory, "award_release_verification", 70,
              "The message asks for verification before releasing an award; "
              "the requested data was not established by this wording alone.",
              "Matched wording: " + awardVerificationPhrase);
  }
  if (paymentAction) {
    addSignal(signals, "payment_action", "Payment or transfer request",
              FinancialCategory, "payment_action", 70,
              "The message asks the recipient to pay, transfer funds, settle a "
              "balance, or change payment details.",
              "Matched wording: " + paymentActionPhrase);
  }
  if (renewalClaim && chargeClaim && recoveryAction) {
    const int strength =
        urgency || hasLink ? (unauthorizedCharge ? 92 : 86) : 68;
    addSignal(signals, "charge_recovery_request",
              "Charge or renewal recovery request", FinancialCategory,
              "charge_recovery", strength,
              "A claimed charge or subscription renewal is paired with a "
              "cancellation, refund, or dispute action. This can be legitimate, "
              "but the combination warrants independent verification.",
              "Renewal/charge wording and recovery wording occur in the same "
              "message.");
    if (hasLink || urgency)
      addSignal(signals, "recovery_bait", "Unexpected charge recovery route",
                ContentCategory, "recovery_bait", 72,
                "A charge or renewal claim directs the recipient to an urgent "
                "cancellation or refund route.",
                "A renewal/charge claim, recovery request, and " +
                    S(hasLink ? "link" : "urgent wording") +
                    " were present.");
  }

  const bool consumerSender = consumerMailbox(senderDomain);
  const SmsOrganization *textOrganization =
      findClaimedOrganization(normalizedMessage);
  const SmsOrganization *senderOrganization =
      findOrganizationByDomain(senderDomain);
  const SmsOrganization *claimedOrganization =
      textOrganization ? textOrganization : senderOrganization;
  if (textOrganization && senderOrganization &&
      textOrganization != senderOrganization) {
    addSignal(signals, "sender_claim_mismatch",
              "Sender domain conflicts with the named organization",
              SenderCategory, "organization_sender_mismatch", 88,
              "The supplied sender domain matches one configured organization "
              "while the message names another.",
              "Message claim: " + textOrganization->name +
                  "; sender-domain match: " + senderOrganization->name);
  } else if (claimedOrganization && !sender.empty() &&
             !matchesOfficialDomain(senderDomain, *claimedOrganization)) {
    S expected;
    for (const S &domain : claimedOrganization->officialDomains) {
      if (!expected.empty())
        expected += ", ";
      expected += domain;
    }
    addSignal(signals, "sender_domain_mismatch",
              "Sender domain does not match the named organization",
              SenderCategory, "organization_sender_mismatch", 82,
              "The message names an organization whose configured official "
              "domains do not include the supplied sender domain.",
              "Claimed organization: " + claimedOrganization->name +
                  "; sender domain: " + senderDomain +
                  "; configured domains: " + expected);
  } else if (claimedOrganization && senderOrganization) {
    positiveEvidence.push_back(
        {{"name", "Sender domain matches a configured organization domain"},
         {"evidence", senderDomain},
         {"status", "heuristic"},
         {"note", "A domain match is not email authentication."}});
  }

  const S senderRolePhrase =
      firstPhrase(wordsOnly(senderDomain),
                  {"account verify", "secure login", "security alert",
                   "billing support", "refund portal", "auto renewal",
                   "payment service", "password reset"});
  if (!claimedOrganization && !sender.empty() && !senderRolePhrase.empty() &&
      (sensitiveRequest || financialAction)) {
    addSignal(signals, "role_branded_sender_domain",
              "Role-branded sender domain with a sensitive request",
              SenderCategory, "role_sender_domain", 58,
              "The sender domain uses account, security, payment, or recovery "
              "language but is not linked to a supported organization "
              "reference.",
              "Sender domain: " + senderDomain);
  }

  if (!sender.empty() && !claimedOrganization &&
      (financialAction || actionableAward || awardContext)) {
    addSignal(signals, "unverified_sender_action",
              "Unverified sender paired with an actionable or award claim",
              SenderCategory, "unverified_sender_action",
              actionableAward || financialAction ? 45 : 35,
              "No supported organization reference matches the sender while "
              "the message contains an actionable request or award claim. "
              "This is uncertainty, not proof of impersonation.",
              "Sender domain: " + senderDomain,
              "unknown");
  }

  if (headers.malformed)
    limitations.push_back(
        "Some supplied header lines could not be interpreted.");
  if (!headers.authenticationResults.empty()) {
    for (const S &method : Args{"spf", "dkim", "dmarc"}) {
      const S result = authenticationResult(headers.authenticationResults,
                                            method);
      if (result == "fail" || result == "softfail" || result == "permerror") {
        addSignal(signals, "auth_" + method + "_" + result,
                  method + " reported " + result, SenderCategory,
                  "authentication_" + method,
                  result == "fail" ? 65 : 52,
                  "The pasted Authentication-Results header reports an "
                  "authentication failure. CyberShield does not validate the "
                  "header cryptographically.",
                  method + "=" + result, "provided_unverified");
      } else if (result == "pass") {
        positiveEvidence.push_back(
            {{"name", method + " pass reported in supplied headers"},
             {"evidence", method + "=pass"},
             {"status", "provided_unverified"},
             {"note", "This header value was not independently verified."}});
      } else {
        limitations.push_back(method +
                              " result was not available in the supplied "
                              "Authentication-Results header.");
      }
    }
  }

  if (!headers.from.empty() && !sender.empty()) {
    try {
      const S headerSender = mailbox(headers.from);
      if (headerSender != sender) {
        addSignal(signals, "from_header_mismatch",
                  "From field differs from supplied From header",
                  SenderCategory, "from_header_mismatch", 75,
                  "The address in the form differs from the From address "
                  "parsed from the supplied headers.",
                  "Form sender: " + sender + "; header From: " + headerSender,
                  "provided_unverified");
      }
    } catch (const Problem &) {
      limitations.push_back(
          "The supplied From header could not be interpreted.");
    }
  }
  if (!headers.replyTo.empty() && !sender.empty()) {
    try {
      const S replyTo = mailbox(headers.replyTo);
      const S replyDomain = emailDomain(replyTo);
      if (replyDomain != senderDomain) {
        addSignal(signals, "reply_to_domain_mismatch",
                  "Reply-To domain differs from sender domain",
                  SenderCategory, "reply_to_mismatch", 58,
                  "Replies would go to a different domain than the displayed "
                  "sender. This can be legitimate, but should be checked.",
                  "From domain: " + senderDomain +
                      "; Reply-To domain: " + replyDomain,
                  "provided_unverified");
      }
    } catch (const Problem &) {
      limitations.push_back(
          "The supplied Reply-To address could not be interpreted.");
    }
  }
  if (!sender.empty() && !claimedOrganization &&
      !senderOrganization && (financialAction || sensitiveRequest)) {
    limitations.push_back(
        "The sender domain is not in the supported organization registry; "
        "its ownership was not verified.");
  }

  std::vector<ParsedEmailLink> parsedLinks;
  J linkReports = J::array();
  for (const EmailLink &link : extraction.links) {
    ParsedEmailLink parsedLink{link, {}, "not_analyzed"};
    const S raw = trim(link.destination);
    const bool encodedRawHost = rawUrlHost(raw).find('%') != S::npos;
    const size_t colon = raw.find(':');
    const size_t slash = raw.find_first_of("/?#");
    if (colon != S::npos &&
        (slash == S::npos || colon < slash) &&
        lowerAscii(raw.substr(0, colon)) != "http" &&
        lowerAscii(raw.substr(0, colon)) != "https") {
      parsedLink.status = "unsupported_scheme";
      addSignal(signals, "unsupported_link_scheme",
                "Unsupported or active link scheme", LinkCategory,
                "unsupported_scheme", 88,
                "The link does not use HTTP or HTTPS and was not opened.",
                raw);
      addExtractionIssue(extraction,
                         "A link used an unsupported or active URL scheme.");
      linkReports.push_back(
          {{"destination", raw},
           {"visible_text", link.visibleText},
           {"source", link.source},
           {"status", parsedLink.status}});
      parsedLinks.push_back(parsedLink);
      continue;
    }

    S candidate = raw;
    if (candidate.rfind("//", 0) == 0)
      candidate = "https:" + candidate;
    else if (candidate.find("://") == S::npos)
      candidate = "https://" + candidate;
    website_inspector::ParsedUrl url;
    S parseError;
    if (!website_inspector::parseUrl(candidate, url, parseError)) {
      parsedLink.status = "parse_failed";
      addExtractionIssue(extraction,
                         "A link destination could not be parsed: " + raw);
      if (encodedRawHost)
        addSignal(signals, "url_encoded_host",
                  "Hostname contains encoded characters", LinkCategory,
                  "url_obscured_destination", 76,
                  "Percent-encoded characters appear in the raw hostname and "
                  "may obscure its actual destination.",
                  raw);
      addSignal(signals, "unparsed_link", "Link could not be analyzed",
                LinkCategory, "unparsed_destination", 30,
                "The destination could not be parsed, so its host and path "
                "were not assessed. This is incomplete evidence, not a safe "
                "verdict.",
                raw, "unknown");
      linkReports.push_back(
          {{"destination", raw},
           {"visible_text", link.visibleText},
           {"source", link.source},
           {"status", parsedLink.status},
           {"error", parseError}});
      parsedLinks.push_back(parsedLink);
      continue;
    }

    parsedLink.host = lowerAscii(url.host);
    parsedLink.status = "analyzed";
    parsedLinks.push_back(parsedLink);
    linkReports.push_back(
        {{"destination", url.url},
         {"host", url.host},
         {"visible_text", link.visibleText},
         {"source", link.source},
         {"status", parsedLink.status}});
    const S urlEvidence = "Destination host: " + url.host +
                          "; URL: " + url.url;
    const size_t labelCount =
        1 + static_cast<size_t>(std::count(url.host.begin(), url.host.end(), '.'));

    if (url.hasUserInfo)
      addSignal(signals, "url_userinfo", "URL contains user information",
                LinkCategory, "url_obscured_destination", 88,
                "Credentials or user information appear before the real host, "
                "which can disguise the destination.",
                urlEvidence);
    if (url.isIp)
      addSignal(signals, "url_ip_host", "Link uses an IP address",
                LinkCategory, "url_host_identity", 78,
                "The destination uses a numeric IP address instead of a "
                "recognizable hostname.",
                urlEvidence);
    if (url.scheme == "http")
      addSignal(signals, "url_http", "Link uses unencrypted HTTP",
                LinkCategory, "url_transport", 38,
                "The link does not protect the connection with HTTPS. This "
                "alone does not prove malicious intent.",
                urlEvidence);
    if (encodedRawHost) {
      addSignal(signals, "url_encoded", "Link contains encoded characters",
                LinkCategory, "url_obscured_destination", 62,
                "Percent-encoded characters make part of the destination "
                "harder to inspect.",
                urlEvidence);
    }
    if (labelCount >= 5)
      addSignal(signals, "url_deep_subdomains", "Unusually deep subdomain",
                LinkCategory, "url_host_structure", 38,
                "The hostname has several subdomain levels. This is a review "
                "signal, not proof of fraud.",
                urlEvidence);
    if (url.url.size() > 150)
      addSignal(signals, "url_long", "Unusually long link", LinkCategory,
                "url_obfuscation", 25,
                "The long URL makes its destination harder to review.",
                urlEvidence);
    if (url.host.find("xn--") != S::npos)
      addSignal(signals, "url_idn", "Internationalized hostname",
                LinkCategory, "url_host_identity", 32,
                "The hostname uses an encoded internationalized label and "
                "should be checked for lookalikes.",
                urlEvidence);
    static const Args shorteners = {
        "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly",
        "rb.gy", "shorturl.at", "rebrand.ly", "ow.ly", "buff.ly"};
    if (linearSearch(shorteners, url.host))
      addSignal(signals, "url_shortener", "Shortened link",
                LinkCategory, "url_destination_hidden", 62,
                "The link uses a shortening service, so the final destination "
                "is not visible in the pasted email.",
                urlEvidence);
    static const Args suspiciousSuffixes = {
        ".zip", ".mov", ".click", ".top", ".work", ".support",
        ".rest", ".country", ".gq", ".tk", ".ml", ".cf",
        ".xyz", ".online", ".site", ".live"};
    for (const S &suffix : suspiciousSuffixes) {
      if (url.host.size() > suffix.size() &&
          url.host.compare(url.host.size() - suffix.size(), suffix.size(),
                           suffix) == 0) {
        addSignal(signals, "url_risk_suffix", "Less common or abuse-prone "
                  "domain suffix", LinkCategory, "url_suffix", 25,
                  "This suffix is sometimes seen in abuse-prone registrations; "
                  "the suffix alone does not establish fraud.",
                  urlEvidence);
        break;
      }
    }
    if ((!url.port.empty() && url.port != "80" && url.port != "443"))
      addSignal(signals, "url_nonstandard_port", "Nonstandard link port",
                LinkCategory, "url_transport", 42,
                "The link uses a nonstandard port.",
                urlEvidence + "; port: " + url.port);
    const S address = lowerAscii(url.url);
    if (address.find("redirect=") != S::npos ||
        address.find("redirect_uri=") != S::npos ||
        address.find("url=https%3a") != S::npos ||
        address.find("next=https%3a") != S::npos ||
        address.find("continue=https%3a") != S::npos) {
      addSignal(signals, "url_redirect_parameter",
                "Link contains a nested redirect destination", LinkCategory,
                "url_redirect", 52,
                "The URL contains a redirect-style parameter. CyberShield "
                "does not follow redirects or open the nested destination.",
                urlEvidence);
    }
    const S pathWords = wordsOnly(url.path);
    if (hasPhrase(pathWords, "login") || hasPhrase(pathWords, "verify") ||
        hasPhrase(pathWords, "account") ||
        hasPhrase(pathWords, "password") ||
        hasPhrase(pathWords, "payment")) {
      if (url.host.find('-') != S::npos || labelCount >= 4)
        addSignal(signals, "url_sensitive_path",
                  "Sensitive action path on a complex hostname", LinkCategory,
                  "url_path_host_combination", 48,
                  "A login, verification, account, or payment path is paired "
                  "with a complex hostname.",
                  urlEvidence);
    }
    bool brandLookalike = false;
    for (const DownloadSourceEntry &source : downloadSourceRegistry()) {
      if (url.host.find(source.host) != S::npos &&
          !domainOrSubdomain(url.host, source.host)) {
        brandLookalike = true;
        break;
      }
    }
    if (brandLookalike)
      addSignal(signals, "url_brand_lookalike",
                "Known publisher name embedded in another hostname",
                LinkCategory, "url_brand_lookalike", 86,
                "A configured publisher domain appears inside a different "
                "hostname. Read the actual destination from right to left.",
                urlEvidence);

    const S displayHost = extractVisibleDomain(link.visibleText);
    if (!displayHost.empty() &&
        !sameDisplayedDomain(displayHost, url.host)) {
      addSignal(signals, "visible_destination_mismatch",
                "Visible link text differs from its destination",
                LinkCategory, "visible_destination_mismatch", 92,
                "The URL-like text shown in the email does not match the "
                "actual link destination.",
                "Displayed host: " + displayHost +
                    "; actual host: " + url.host);
    }
    if (claimedOrganization) {
      if (matchesOfficialDomain(url.host, *claimedOrganization)) {
        positiveEvidence.push_back(
            {{"name", "Link host matches a configured organization domain"},
             {"evidence", url.host + " · " + claimedOrganization->name},
             {"status", "heuristic"},
             {"note", "A domain match does not prove the message or link is "
                      "safe."}});
      } else {
        addSignal(signals, "organization_link_mismatch",
                  "Link does not match the named organization's domains",
                  LinkCategory, "organization_link_mismatch", 90,
                  "The message names an organization, but the actual link host "
                  "is outside the configured official-domain references.",
                  "Claimed organization: " + claimedOrganization->name +
                      "; actual host: " + url.host);
      }
    } else if (!senderDomain.empty() &&
               !sameDisplayedDomain(senderDomain, url.host) &&
               (financialAction || sensitiveRequest || actionableAward ||
                urgency)) {
      addSignal(signals, "sender_link_domain_mismatch",
                "Link host differs from the displayed sender domain",
                LinkCategory, "sender_link_domain_mismatch",
                financialAction || sensitiveRequest || actionableAward
                    ? 64
                    : consumerSender && serviceClaim ? 65 : 42,
                "The message directs the recipient to a host different from "
                "the displayed sender's domain. This is a heuristic signal, "
                "not verified ownership evidence.",
                "Sender domain: " + senderDomain +
                    "; actual link host: " + url.host);
    }
  }

  if (!hasLink &&
      firstPhrase(words, {"click here", "click the link", "open this link",
                          "visit the link", "tap the link", "use this link"}) !=
          "") {
    addExtractionIssue(
        extraction,
        "The message asks the recipient to use a link, but no URL was present "
        "in the supplied text.");
  }
  if (!extraction.complete) {
    for (const S &issue : extraction.issues)
      if (std::find(limitations.begin(), limitations.end(), issue) ==
          limitations.end())
        limitations.push_back(issue);
    addSignal(signals, "link_analysis_incomplete",
              "Link analysis is incomplete", LinkCategory,
              "incomplete_url_analysis", 28,
              "One or more link destinations could not be reliably extracted "
              "or parsed. An incomplete check is not evidence that the link is "
              "safe.",
              extraction.issues.empty()
                  ? "At least one destination was not fully analyzed."
                  : extraction.issues.front(),
              "unknown");
  }
  if (!claimedOrganization && consumerSender && serviceClaim && hasLink &&
      urgency) {
    addSignal(signals, "urgent_delivery_link",
              "Urgent delivery claim paired with an external link",
              ContentCategory, "delivery_link_lure", 65,
              "A consumer mailbox sends an urgent parcel or delivery claim "
              "that directs the recipient to an external link.",
              "Delivery-related wording, urgency, a consumer sender, and a "
              "link were detected.");
  }

  const bool hasFinancialContext =
      chargeClaim || renewalClaim ||
      firstPhrase(words, {"payment", "invoice", "subscription", "refund",
                          "debited", "annual plan"}) != "";
  if (!claimedOrganization && consumerSender &&
      (hasFinancialContext || serviceClaim) &&
      hasLink && (urgency || financialAction)) {
    addSignal(signals, "consumer_sender_linked_service_claim",
              "Consumer mailbox paired with a linked service claim",
              SenderCategory, "consumer_sender_context", 55,
              "A consumer mailbox is used for a financial or service-related "
              "claim that directs the recipient to an external link. A free "
              "mailbox alone is not treated as malicious.",
              "Sender domain: " + senderDomain +
                  "; financial/service claim and link are present.");
  }

  const J scores = categoryScores(signals);
  const int baseScore = weightedScore(scores);
  Args interactionExplanations;
  const int adjustment = interactionBonus(scores, interactionExplanations);
  const int score = std::max(0, std::min(100, baseScore + adjustment));
  const S category = riskCategory(score);

  int confidence = 100;
  Args missingEvidence;
  if (sender.empty()) {
    confidence -= 15;
    missingEvidence.push_back("No sender address was supplied or extracted.");
  }
  if (subject.empty()) {
    confidence -= 10;
    missingEvidence.push_back("No subject was supplied.");
  }
  if (rawHeaders.empty()) {
    confidence -= 20;
    missingEvidence.push_back(
        "Original headers were not supplied; SPF, DKIM, and DMARC could not "
        "be assessed.");
  } else if (headers.authenticationResults.empty()) {
    confidence -= 15;
    missingEvidence.push_back(
        "No Authentication-Results field was found in the supplied headers.");
  }
  if (headers.malformed) {
    confidence -= 10;
    missingEvidence.push_back(
        "Some supplied header lines could not be interpreted.");
  }
  if (!extraction.complete) {
    confidence -= 25;
    missingEvidence.push_back(
        "At least one link could not be fully analyzed.");
  }
  confidence = std::max(0, std::min(100, confidence));
  const bool complete = extraction.complete && !headers.malformed;

  J findings = J::array();
  std::sort(signals.begin(), signals.end(),
            [](const EmailSignal &left, const EmailSignal &right) {
              if (left.strength != right.strength)
                return left.strength > right.strength;
              if (left.category != right.category)
                return left.category < right.category;
              return left.id < right.id;
            });
  for (const EmailSignal &signal : signals) {
    const int weight =
        signal.category == UrgencyCategory
            ? email_risk::config::UrgencyWeight
        : signal.category == LinkCategory
            ? email_risk::config::LinkWeight
        : signal.category == SenderCategory
            ? email_risk::config::SenderWeight
        : signal.category == FinancialCategory
            ? email_risk::config::FinancialWeight
            : email_risk::config::ContentWeight;
    const S explanation =
        signal.explanation + " Indicator strength: " +
        std::to_string(signal.strength) + "/100; " +
        categoryLabel(signal.category) + " has " + std::to_string(weight) +
        "% weight in the final score.";
    findings.push_back(
        {{"id", signal.id},
         {"name", signal.name},
         {"category", categoryLabel(signal.category)},
         {"severity", signal.severity},
         {"text", explanation},
         {"evidence", signal.evidence},
         {"evidence_status", signal.evidenceStatus},
         {"strength", signal.strength},
         {"dimension_weight", weight},
         {"occurrences", signal.occurrences}});
  }

  J limitationsJson = J::array();
  Args emittedLimitations;
  for (const S &limitation : limitations)
    if (std::find(emittedLimitations.begin(), emittedLimitations.end(),
                  limitation) == emittedLimitations.end()) {
      limitationsJson.push_back(limitation);
      emittedLimitations.push_back(limitation);
    }
  if (limitationsJson.empty())
    limitationsJson.push_back(
        "The analysis uses local rules and does not connect to Gmail or an "
        "external reputation service.");
  J missingJson = J::array();
  for (const S &item : missingEvidence)
    missingJson.push_back(item);

  int analyzedLinks = 0;
  for (const auto &link : parsedLinks)
    analyzedLinks += link.status == "analyzed" ? 1 : 0;
  const S summary =
      conciseSummary(scores, category, signals, interactionExplanations,
                     adjustment);
  J assessment = {
      {"category_scores", scores},
      {"weights",
       {{UrgencyCategory, email_risk::config::UrgencyWeight},
        {LinkCategory, email_risk::config::LinkWeight},
        {SenderCategory, email_risk::config::SenderWeight},
        {FinancialCategory, email_risk::config::FinancialWeight},
        {ContentCategory, email_risk::config::ContentWeight}}},
      {"weighted_score", baseScore},
      {"interaction_adjustment", adjustment},
      {"interaction_explanations", interactionExplanations},
      {"summary", summary},
      {"confidence",
       {{"score", confidence},
        {"label", confidenceLabel(confidence)},
        {"complete", complete},
        {"missing_evidence", missingJson}}},
      {"sender_status",
       sender.empty()
           ? "unknown"
           : claimedOrganization
                 ? matchesOfficialDomain(senderDomain, *claimedOrganization)
                       ? "domain_matches_reference_heuristic"
                       : "domain_mismatch"
                 : "unverified"},
      {"links",
       {{"found", extraction.links.size()},
        {"analyzed", analyzedLinks},
        {"complete", extraction.complete},
        {"items", linkReports},
        {"issues", extraction.issues}}},
      {"positive_evidence", positiveEvidence},
      {"limitations", limitationsJson}};
  J notes = J::array(
      {summary,
       "Risk is a weighted local assessment, not a probability or a guarantee "
       "of safety.",
       "Email content and URLs are analyzed locally. URLs are not opened and "
       "redirect destinations are not followed.",
       "Sender domains and authentication results supplied by the user are "
       "not independently authenticated."});
  if (!claimedOrganization)
    notes.push_back(
        "No supported organization was identified for an official-domain "
        "comparison.");

  S advice;
  if (score >= email_risk::config::HighRiskThreshold)
    advice =
        "Do not click links, reply, provide credentials, or pay. Contact the "
        "organization using a separately obtained official app or address.";
  else if (score >= email_risk::config::SuspiciousThreshold)
    advice =
        "Do not use the email's links for sensitive actions. Verify the "
        "request through an independently obtained official channel.";
  else if (score >= email_risk::config::CautionThreshold)
    advice =
        "Review the evidence and verify any request independently before "
        "sharing sensitive information.";
  else
    advice =
        "No strong configured risk signals were found in the supplied text. "
        "This does not verify the sender or guarantee the email is safe.";

  J report = {{"type", "Email"},
              {"target", "Email analysis"},
              {"category", category},
              {"score", score},
              {"findings", findings},
              {"notes", notes},
              {"advice", advice},
              {"source", "CyberShield local email analysis engine"},
              {"email_assessment", assessment}};
  return report;
}
