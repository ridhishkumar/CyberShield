#include "download_sources.h"
#include "dsa.h"
#include <asio/ip/address.hpp>
#include <regex>
#include <sstream>
using Findings = std::vector<Finding>;
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
                         "send your code",
                         "share your otp",
                         "share the code",
                         "provide your otp",
                         "send your otp",
                         "reply with your otp",
                         "reply with the code",
                         "reply with your verification code",
                         "send your verification code",
                         "send me the verification code"};
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
static bool hasPhrase(const S &normalized, const S &phrase) {
  return (" " + normalized + " ").find(" " + phrase + " ") != S::npos;
}
static bool sharedHost(const S &host) {
  return linearSearch({"github.com", "sourceforge.net", "apps.microsoft.com",
                       "store.steampowered.com", "play.google.com",
                       "apps.apple.com"},
                      host);
}
static bool pathMatch(const S &path, const S &prefix) {
  // An encoded or relative path may be interpreted differently by the server.
  if (path.find('%') != S::npos || path.find("/./") != S::npos ||
      (path + "/").find("/../") != S::npos)
    return false;
  return prefix == "/" || path == prefix || path.rfind(prefix + "/", 0) == 0;
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
  if (url.size() > 150)
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
  if (std::count(url.begin(), url.end(), '%') >= 5)
    f.push_back({"The URL contains many percent-encoded characters, making its destination harder to read.", 10});
  if (std::count(url.begin(), url.end(), '?') > 1 ||
      std::count(url.begin(), url.end(), '&') >= 8)
    f.push_back({"The URL contains an unusually complex query string.", 8});
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
  for (const auto &product : downloadCatalogue()) {
    for (const auto &ref : product.sources) {
      const S official =
          ref.host.rfind("www.", 0) == 0 ? ref.host.substr(4) : ref.host;
      if (!sharedHost(official) &&
          ("." + host + ".").find("." + official + ".") != S::npos &&
          host != official &&
          (host.size() <= official.size() ||
           host.compare(host.size() - official.size() - 1, official.size() + 1,
                        "." + official) != 0))
        imitatedHost = true;
    }
  }
  if (imitatedHost)
    f.push_back({"A publisher domain appears inside a different hostname. Read "
                 "the destination from right to left.",
                 35});
  if (at != S::npos || scheme != "https" ||
      (!port.empty() && port != (scheme == "https" ? "443" : "80"))) {
    if (outPath)
      outPath->clear();
  }
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
J softwareSources() {
  J entries = J::array();
  for (const auto &product : downloadCatalogue()) {
    const auto &ref = product.sources.front();
    entries.push_back({{"product", product.label},
                       {"url", "https://" + ref.host + ref.path}});
  }
  return entries;
}
J analyze(const S &type, const J &j) {
  Findings f;
  S target, source = "Local, transparent rules",
            advice = "Verify the destination through an independently obtained "
                     "official address.";
  J notes = J::array();
  S hostname;
  bool knownSource = false;
  int confidencePenalty = 0;
  S path, basis;
  if (type == "Website" || type == "Software") {
    const bool software = type == "Software";
    S submitted = field(j, "url", 2048, !software);
    S app, publisher;
    if (software) {
      app = field(j, "name", 120, false);
      publisher = field(j, "publisher", 120, false);
      if (app.find_first_not_of(" \t\n\r") == S::npos && submitted.empty())
        throw Problem(400, "Enter the software name or its download address.");
    }
    if (!submitted.empty()) {
      hostname = website(submitted, f, &path);
      target = hostname;
      const S address = lower(submitted);
      const bool http =
          address.find("http://") == address.find_first_not_of(" \t\n\r");
      notes.push_back("Source host: " + hostname);
      notes.push_back(http ? "The address uses HTTP."
                           : "The address uses or defaults to HTTPS.");
      S context = lower(field(j, "description", 1500, false));
      std::smatch expected;
      if (std::regex_search(context, expected,
                            std::regex(R"(https?://([a-z0-9.-]+))")) &&
          expected[1].str() != hostname)
        notes.push_back("The context mentions a different host. Confirm the "
                        "intended service.");
    }
    S productName = wordsOnly(
        std::regex_replace(lower(app), std::regex("[.](exe|msi|dmg)$"), ""));
    const Product *match = nullptr;
    for (const auto &product : downloadCatalogue()) {
      if (software && !linearSearch(product.names, productName))
        continue;
      if (software)
        match = &product;
      for (const auto &ref : product.sources) {
        if (!path.empty() && hostname == ref.host &&
            pathMatch(path, ref.path) &&
            (hostname != "github.com" || path == ref.path ||
             path == ref.path + "/" || pathMatch(path, ref.path + "/releases")))
          knownSource = true;
      }
    }
    if (software) {
      target = app.empty() ? hostname : app;
      if (!publisher.empty())
        notes.push_back("Declared publisher: " + publisher);
      if (containsAny(wordsOnly(app + " " + submitted),
                      {"keygen", "cracked", "crack installer"}))
        f.push_back(
            {"The name or download address suggests unofficial distribution.",
             40});
      if (match) {
        const auto &ref = match->sources.front();
        notes.push_back("Official reference: https://" + ref.host + ref.path);
        if (!hostname.empty() && !knownSource)
          f.push_back({"The download location differs from the listed sources "
                       "for this product.",
                       20});
        if (!publisher.empty() &&
            !linearSearch(match->publishers, wordsOnly(publisher))) {
          f.push_back({"The declared publisher differs from the publisher "
                       "listed for this product.",
                       25});
          knownSource = false;
        }
      }
      if (app.empty())
        basis = "The download address was checked. Add the application name to "
                "compare it with its publisher.";
      else if (knownSource)
        basis =
            "The product and download location match a publisher reference.";
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
    } else {
      basis = knownSource
                  ? "The address matches a location in the publisher reference "
                    "catalogue. The page contents have not been inspected."
                  : "CyberShield has no verified trust evidence for this "
                    "address. A well-formed hostname and HTTPS alone do not "
                    "establish safety.";
    }
    // A missing publisher match is an evidence gap, not proof of a scam.
    confidencePenalty += knownSource ? 15 : 30;
    if (!knownSource) {
      f.push_back({software ? "Source verification allowance: the product and "
                              "source could not be confirmed together."
                            : "Source verification allowance: the address has "
                              "no match in the local publisher directory.",
                   10});
    }
    notes.push_back(
        "Risk points are the sum of detected indicators (capped at 100). The trust score starts at 100, subtracts risk points and an evidence-gap penalty. It is a screening estimate, not a probability or guarantee.");
    notes.push_back(
        "Assessment uses URL structure and bundled publisher references. The checker does not open or execute the website, inspect its live page, or establish domain age or ownership.");
  } else {
    const bool sms = type == "SMS";
    S body = field(j, "content", sms ? 5000 : 20000);
    S sender, subject, headers;
    if (sms) {
      const S phone = field(j, "phone", 32, false);
      if (!phone.empty()) {
        size_t digits = std::count_if(phone.begin(), phone.end(), [](char c) {
          return c >= '0' && c <= '9';
        });
        if (phone.find_first_not_of("+0123456789 ()-") != S::npos ||
            phone.find('+', 1) != S::npos || digits < 3 || digits > 15)
          throw Problem(
              400,
              "Enter a sender number with 3 to 15 digits, or leave it blank.");
        notes.push_back(digits <= 6 ? "Sender format resembles a short code."
                        : phone.front() == '+'
                            ? "Sender number uses international format."
                            : "Sender number uses national format.");
      }
      notes.push_back("A displayed sender number can be spoofed. Number "
                      "ownership is unverified.");
    } else {
      sender = field(j, "sender", 254, false);
      subject = field(j, "subject", 300, false);
      headers = field(j, "headers", 8192, false);
      if (!sender.empty())
        sender = mailbox(sender);
    }
    S text = lower(body + " " + subject);
    target = sms ? "SMS message" : "Email analysis";
    advice = "Confirm unexpected requests independently using the "
             "organisation's official app or a trusted contact number.";
    const S words = wordsOnly(text);
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
    if (containsAny(text, {"urgent", "immediately", "within 24 hours",
                           "suspended", "final warning"}))
      f.push_back({"Urgency or account pressure appears in the message.", 25});
    if (asksForSecret(text))
      f.push_back(
          {"The message asks for credentials or a verification code.", 40});
    if (containsAny(text, {"your parcel", "redelivery", "delivery failed"}) &&
        containsAny(text, {"pay", "fee", "payment"}))
      f.push_back({"A delivery claim is paired with a payment request.", 30});
    if (containsAny(text, {"wire transfer", "gift card", "bank details",
                           "credit card"}))
      f.push_back({"A payment or financial-data request appears.", 30});
    if (containsAny(text, {"won a prize", "claim your reward", "lottery"}))
      f.push_back({"Unexpected prize or reward language appears.", 25});
    if (containsAny(text, {".exe", ".scr", "enable macros"}))
      f.push_back({"The message mentions executable content or macros.", 25});
    std::istringstream tokens(body);
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
                           "verify your identity", "reactivate your account"}))
      f.push_back(
          {"An account or identity verification request includes a web link.",
           25});
    int flaggedLinks = 0;
    Args flaggedHosts;
    while (!links.empty()) {
      Findings link;
      try {
        const S foundHost = website(links.pop(), link);
        if (!link.empty()) {
          ++flaggedLinks;
          if (!linearSearch(flaggedHosts, foundHost) && flaggedHosts.size() < 5)
            flaggedHosts.push_back(foundHost);
        }
      } catch (const Problem &) {
        continue;
      }
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
    notes.push_back("The trust score accounts for missing sender and authentication evidence. Supplied headers are parsed as claims and are not cryptographically verified by CyberShield.");
  sortFindings(f);
  J findings = J::array();
  int score = 0;
  for (auto &row : f) {
    findings.push_back({{"text", row.text}, {"points", row.points}});
    score += row.points;
  }
  score = std::min(score, 100);
  const int trustScore = std::max(0, std::min(100, 100 - score - confidencePenalty));
  S category = score >= 60   ? "High risk"
               : score >= 25 ? "Suspicious"
                             : "Lower risk";
  J report = {{"type", type},         {"target", target},     {"score", score},
              {"trust_score", trustScore}, {"confidence_penalty", confidencePenalty},
              {"category", category}, {"findings", findings}, {"notes", notes},
              {"advice", advice},     {"source", source}};
  if (!basis.empty())
    report["basis"] = basis;
  if (!hostname.empty())
    report["hostname"] = hostname;
  return report;
}
