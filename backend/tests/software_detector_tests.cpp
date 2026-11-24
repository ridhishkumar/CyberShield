#include "app.h"
#include "software_analyzer.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <stdexcept>

std::filesystem::path root;
J softwareSources();

S lower(S value) {
  for (char &c : value)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}

S field(const J &input, const S &name, size_t max, bool required) {
  const auto found = input.find(name);
  if (found == input.end() || found->is_null()) {
    if (required)
      throw Problem(400, "Missing field.");
    return {};
  }
  if (!found->is_string())
    throw Problem(400, "Invalid field.");
  S value = found->get<S>();
  if (value.size() > max)
    throw Problem(400, "Field too long.");
  return value;
}

static J scan(const S &name, const S &url = "", const S &publisher = "") {
  return analyze("Software",
                 {{"name", name}, {"url", url}, {"publisher", publisher}});
}

static J scanSms(const S &content, const S &sender = "") {
  return analyze("SMS", {{"content", content}, {"sender", sender}});
}

static J scanEmail(const S &sender, const S &subject, const S &content,
                   const S &headers = "") {
  return analyze("Email",
                 {{"sender", sender},
                  {"subject", subject},
                  {"content", content},
                  {"headers", headers}});
}

static int emailDimension(const J &report, const S &key) {
  return report.at("email_assessment").at("category_scores").at(key).get<int>();
}

static int smsDimension(const J &report, const S &key) {
  return report.at("sms_assessment").at("category_scores").at(key).get<int>();
}

static S expectedSmsCategory(int score) {
  if (score >= 61)
    return "Highly Risky";
  if (score >= 36)
    return "Be Cautious";
  return "Safe";
}

static bool smsClassificationConsistent(const J &report) {
  return report.at("category") ==
         expectedSmsCategory(report.at("score").get<int>());
}

static bool hasEmailSignal(const J &report, const S &id) {
  for (const auto &finding : report.at("findings"))
    if (finding.value("id", S()) == id)
      return true;
  return false;
}

static bool hasSmsSignal(const J &report, const S &id) {
  for (const auto &finding : report.at("findings"))
    if (finding.value("id", S()) == id)
      return true;
  return false;
}

static bool hasSoftwareSignal(const J &report, const S &id) {
  for (const auto &signal : report.at("software_assessment").at("signals"))
    if (signal.value("id", S()) == id)
      return true;
  return false;
}

static bool invalidSoftwareUrl(const S &url) {
  try {
    scan("", url);
  } catch (const Problem &error) {
    return error.status == 400;
  }
  return false;
}

static J softwareBoundaryReport(int score) {
  J signals = J::array();
  signals.push_back({{"id", "boundary_source"},
                     {"category", "source_domain"},
                     {"family", "boundary_source"},
                     {"score", score},
                     {"confidence", 100},
                     {"verification_status", "test"}});
  if (score >= 61)
    signals.push_back({{"id", "declared_publisher_mismatch"},
                       {"category", "publisher_consistency"},
                       {"family", "boundary_publisher"},
                       {"score", score},
                       {"confidence", 100},
                       {"verification_status", "configured_reference_comparison"}});
  return scoreSoftwareReport(
      {{"type", "Software"},
       {"hostname", "boundary.example.test"},
       {"source_status", "VERIFIED_OFFICIAL"},
       {"notes", J::array()}},
      signals, J::object(), J::object());
}

int main() {
  try {
  if (softwareSources().size() != 64)
    throw std::runtime_error("The configured software source list is incomplete.");
  const J unknown = scan("Unlisted Utility");
  if (unknown["score"] != 0 || !unknown["trust_score"].is_null() ||
      unknown["category"] != "Safe" ||
      unknown["source_verification"]["status"] != "UNVERIFIED")
    throw std::runtime_error(
        "Unknown software must not receive an unsupported risk score.");

  const J nameOnly = scan("VLC");
  if (nameOnly["score"] != 0 || !nameOnly["trust_score"].is_null() ||
      nameOnly["category"] != "Safe" ||
      nameOnly["source_verification"]["status"] != "UNVERIFIED")
    throw std::runtime_error("A product name alone must remain unverified.");

  const J officialVersioned = scan(
      "VLC media player 3.0.20 x64 installer",
      "https://videolan.org/vlc/", "VideoLAN");
  if (officialVersioned["score"] != 0 ||
      !officialVersioned["trust_score"].is_null() ||
      officialVersioned["category"] != "Safe" ||
      officialVersioned["source_verification"]["status"] !=
          "VERIFIED_OFFICIAL" ||
      officialVersioned["software_assessment"]["category_scores"]
                        ["source_domain"] != 0)
    throw std::runtime_error("Official versioned VLC source did not match.");

  const J vlcExact =
      scan("VLC Media Player", "https://www.videolan.org/vlc/", "VideoLAN");
  if (vlcExact["source_status"] != "VERIFIED_OFFICIAL" ||
      vlcExact["category"] != "Safe" ||
      vlcExact["score"].get<int>() != 0)
    throw std::runtime_error(
        "The exact official VLC source did not remain low risk.");

  const J sevenZipOfficial =
      scan("7-Zip", "https://www.7-zip.org/", "Igor Pavlov");
  if (sevenZipOfficial["source_status"] != "VERIFIED_OFFICIAL" ||
      sevenZipOfficial["score"].get<int>() > 15 ||
      sevenZipOfficial["category"] != "Safe")
    throw std::runtime_error(
        "The official 7-Zip homepage was not verified as low risk.");

  const J vlcHomepage =
      scan("VLC Media Player", "https://www.videolan.org/", "VideoLAN");
  if (vlcHomepage["source_status"] != "VERIFIED_OFFICIAL" ||
      vlcHomepage["score"].get<int>() > 15 ||
      vlcHomepage["category"] != "Safe")
    throw std::runtime_error(
        "The official VLC homepage was not verified as low risk.");

  const J blender = analyze(
      "Software",
      {{"name", "Blender"},
       {"url", "https://www.blender.org/download/"},
       {"publisher", "Blender Foundation"},
       {"description",
        "Official Blender download page. Free and open-source 3D creation "
        "software. Testing source verification, publisher matching, URL "
        "analysis, and risk scoring."}});
  if (blender["source_status"] != "VERIFIED_OFFICIAL" ||
      blender["source_verification"]["status"] != "VERIFIED_OFFICIAL" ||
      blender["category"] != "Safe" ||
      blender["score"].get<int>() != 0 ||
      blender["software_assessment"]["category_scores"]["source_domain"] != 0 ||
      blender.contains("file_details") ||
      !blender["software_assessment"]["confidence"].is_object() ||
      !blender["software_assessment"]["completeness"].is_object() ||
      blender["software_assessment"]["confidence"]["score"] ==
          blender["software_assessment"]["completeness"]["score"] ||
      hasSoftwareSignal(blender, "declared_publisher_mismatch") ||
      blender["software_assessment"]["positive_evidence"]
              .dump()
              .find("declared publisher matches") == S::npos ||
      blender["software_assessment"]["positive_evidence"]
              .dump()
              .find("configured local official-source reference") == S::npos ||
      blender["software_assessment"]["limitations"]
              .dump()
              .find("No downloaded file was supplied") == S::npos)
    throw std::runtime_error(
        "The official Blender URL was not distinguished from file "
        "verification or publisher mismatch.");

  const J novaEdit =
      scan("NovaEdit", "https://downloads.example.test/novaedit/",
           "NovaEdit Software");
  if (novaEdit["source_status"] != "UNVERIFIED" ||
      novaEdit["score"].get<int>() < 61 ||
      novaEdit["category"] != "Highly Risky" ||
      novaEdit["source_reference"].is_object() ||
      novaEdit["advice"].get<S>().find("Do not download from this address") ==
          S::npos ||
      hasSoftwareSignal(novaEdit, "unverified_source"))
    throw std::runtime_error(
        "An unknown NovaEdit source was presented as trusted or recommended: " +
        novaEdit.dump());

  const J ultraPdf =
      scan("UltraPDF Pro",
           "https://ultrapdf-download.example.test/free-download",
           "UltraPDF Technologies");
  if (ultraPdf["source_status"] != "UNVERIFIED" ||
      ultraPdf["source_verification"]["status"] != "UNVERIFIED" ||
      ultraPdf["score"].get<int>() < 61 ||
      ultraPdf["category"] != "Highly Risky" ||
      ultraPdf.contains("source_reference"))
    throw std::runtime_error(
        "An unverified UltraPDF download was not rated high risk.");

  const J firefoxUnknown =
      scan("Mozilla Firefox", "https://www.mozilla.org/",
           "Unknown Publisher");
  if (firefoxUnknown["source_status"] != "VERIFIED_OFFICIAL" ||
      firefoxUnknown["score"].get<int>() < 36 ||
      firefoxUnknown["score"].get<int>() > 60 ||
      firefoxUnknown["category"] != "Be Cautious" ||
      !hasSoftwareSignal(firefoxUnknown, "publisher_identity_uncertain"))
    throw std::runtime_error(
        "Unknown Firefox publisher identity was not represented as caution.");

  const J subdomain = scan("", "https://store.blender.org/download");
  if (subdomain["source_status"] != "VERIFIED_OFFICIAL" ||
      subdomain["score"].get<int>() != 0)
    throw std::runtime_error(
        "A structurally valid subdomain of a configured official domain was "
        "not recognized.");

  const J normalizedDomain =
      scan("", "HTTPS://WWW.BLENDER.ORG.:443/download/?mirror=1");
  if (normalizedDomain["source_status"] != "VERIFIED_OFFICIAL" ||
      normalizedDomain["score"].get<int>() != 0)
    throw std::runtime_error(
        "Hostname case, trailing dot, port, or query parsing changed source "
        "verification.");

  const J unknownOrdinary = scan("", "https://example.net/download?mirror=1");
  if (unknownOrdinary["source_status"] != "UNVERIFIED" ||
      unknownOrdinary["score"].get<int>() < 61 ||
      unknownOrdinary["category"] != "Highly Risky")
    throw std::runtime_error(
        "An ordinary unknown source was treated as positive risk evidence.");

  const J unknownInsufficient = scan("", "https://new-site.example/download");
  if (unknownInsufficient["score"].get<int>() < 61 ||
      unknownInsufficient["category"] != "Highly Risky" ||
      unknownInsufficient["source_verification"]["status"] != "UNVERIFIED")
    throw std::runtime_error(
        "Insufficient source information was treated as malicious evidence.");

  const J lookalike = scan("VLC 3.0.20",
                           "https://videolan.org.evil.test/vlc");
  if (lookalike["score"].get<int>() < 61 ||
      !lookalike["trust_score"].is_null() ||
      lookalike["category"] != "Highly Risky" ||
      lookalike["source_verification"]["status"] != "SUSPICIOUS" ||
      lookalike.contains("source_reference"))
    throw std::runtime_error(
        "A single lookalike indicator was not rated suspicious or was "
        "overstated as high risk.");

  const J publisherLookalike =
      scan("VLC Media Player", "https://videolan-download.example.test/setup/",
           "VideoLAN");
  if (publisherLookalike["source_verification"]["status"] != "SUSPICIOUS" ||
      publisherLookalike.contains("source_reference") ||
      publisherLookalike["advice"].get<S>().find(
          "Do not download from this address") == S::npos)
    throw std::runtime_error(
        "A publisher-branded lookalike host was treated as a trusted source.");

  const J brandedLookalike =
      scan("Google Chrome 138", "https://google-chrome-login.xyz/login");
  if (brandedLookalike["score"].get<int>() < 20 ||
      brandedLookalike["score"].get<int>() >= 70 ||
      !hasSoftwareSignal(brandedLookalike, "product_source_mismatch"))
    throw std::runtime_error(
        "A product-branded hostname on an unrelated domain was not reported.");

  const J crack = scan("VLC cracked installer");
  if (crack["score"].get<int>() < 40 || !crack["trust_score"].is_null() ||
      crack["category"] != "Be Cautious")
    throw std::runtime_error("Cracked software indicator was not detected.");

  const J recognizedHost = scan("", "blender.org");
  if (recognizedHost["hostname"] != "blender.org" ||
      recognizedHost["score"].get<int>() > 50 ||
      recognizedHost["source_status"] != "VERIFIED_OFFICIAL")
    throw std::runtime_error("An exact allowlisted hostname was not recognized.");

  const J ordinaryUrl =
      scan("", "https://blender.org/download/stable-x64?mirror=1&os=windows");
  if (ordinaryUrl["score"].get<int>() > 50 ||
      ordinaryUrl["source_status"] != "VERIFIED_OFFICIAL")
    throw std::runtime_error("Ordinary path punctuation raised source risk.");

  const J suspiciousOfficialUrl =
      scan("", "https://visitor@blender.org/download");
  if (suspiciousOfficialUrl["source_status"] != "SUSPICIOUS" ||
      suspiciousOfficialUrl["score"].get<int>() < 61 ||
      suspiciousOfficialUrl["category"] != "Highly Risky" ||
      suspiciousOfficialUrl.contains("source_reference"))
    throw std::runtime_error(
        "A strong but single URL warning was not reported proportionately.");

  const J insecureOfficialUrl =
      scan("", "http://blender.org/download?mirror=stable");
  if (insecureOfficialUrl["source_status"] != "UNVERIFIED" ||
      insecureOfficialUrl["score"].get<int>() < 61 ||
      insecureOfficialUrl["category"] != "Highly Risky")
    throw std::runtime_error("HTTP risk was not applied to a listed source.");

  const J wwwAlias = scan("", "www.blender.org");
  if (wwwAlias["source_status"] != "VERIFIED_OFFICIAL" ||
      wwwAlias["score"].get<int>() != 0)
    throw std::runtime_error(
        "A valid subdomain did not match the configured official domain.");

  const J unrelatedRootPath = scan("", "https://7-zip.org/archive/old");
  if (unrelatedRootPath["source_status"] != "UNVERIFIED" ||
      unrelatedRootPath["score"].get<int>() < 61)
    throw std::runtime_error(
        "A known publisher domain with an unlisted path was mislabeled as "
        "malicious.");

  const J verifiedWwwAlias =
      scan("", "https://www.microsoft.com/en-in/software-download/windows11");
  if (verifiedWwwAlias["source_status"] != "VERIFIED_OFFICIAL" ||
      verifiedWwwAlias["score"].get<int>() > 50)
    throw std::runtime_error("A verified official www download page was rejected.");

  const J verifiedDownloadHost =
      scan("", "https://downloads.vivaldi.com/stable/browser.exe");
  if (verifiedDownloadHost["source_status"] != "VERIFIED_OFFICIAL" ||
      verifiedDownloadHost["score"].get<int>() > 50)
    throw std::runtime_error("A verified official download host was rejected.");

  const J verifiedProjectDownload =
      scan("", "https://download.gimp.org/gimp/v3.2/linux/gimp.AppImage");
  if (verifiedProjectDownload["source_status"] != "VERIFIED_OFFICIAL" ||
      verifiedProjectDownload["score"].get<int>() > 50)
    throw std::runtime_error("A verified GIMP download host was rejected.");

  const J scopedSharedHost =
      scan("", "https://github.com/unrelated/project/releases/download/v1/app");
  if (scopedSharedHost["source_status"] != "UNVERIFIED" ||
      scopedSharedHost["score"].get<int>() < 61)
    throw std::runtime_error("A shared code host was trusted outside its path.");

  const J unlisted = scan("", "https://example.net/download?mirror=1");
  if (unlisted["score"].get<int>() < 61 ||
      unlisted["category"] != "Highly Risky" ||
      unlisted["source_verification"]["status"] != "UNVERIFIED" ||
      unlisted["hostname"] != "example.net")
    throw std::runtime_error(
        "An unlisted source was incorrectly assigned baseline risk.");

  const J suffixLookalike =
      scan("", "https://microsoft.com.example.net/download");
  if (suffixLookalike["score"].get<int>() < 45 ||
      suffixLookalike["score"].get<int>() < 61 ||
      suffixLookalike["source_status"] != "SUSPICIOUS" ||
      suffixLookalike["category"] != "Highly Risky")
    throw std::runtime_error(
        "A deceptive Microsoft hostname was accepted or overstated.");

  const J nestedLookalike =
      scan("", "https://blender.org.fake-site.net/download");
  const J prefixLookalike = scan("", "https://fakeblender.org/download");
  if (nestedLookalike["source_status"] != "SUSPICIOUS" ||
      prefixLookalike["source_status"] != "SUSPICIOUS" ||
      nestedLookalike.contains("source_reference") ||
      prefixLookalike.contains("source_reference") ||
      nestedLookalike["category"] != "Highly Risky" ||
      prefixLookalike["category"] != "Highly Risky")
    throw std::runtime_error(
        "A suffix or prefix lookalike inherited official-domain trust.");

  const J numericHost = scan("", "http://192.0.2.1/download");
  if (numericHost["score"].get<int>() < 45 ||
      numericHost["score"].get<int>() < 61 ||
      numericHost["source_status"] != "SUSPICIOUS")
    throw std::runtime_error(
        "A numeric IP host was not flagged proportionately.");

  const J encodedHost = scan("", "https://google%2ecom/chrome");
  if (encodedHost["hostname"] != "google.com" ||
      encodedHost["score"].get<int>() < 25 ||
      encodedHost["source_status"] != "SUSPICIOUS")
    throw std::runtime_error("Encoded hostname characters were not reported.");

  const J severeSource =
      scan("", "http://microsoft.com.example.net/verify-account"
                "?redirect=https%3A%2F%2Fattacker.example");
  if (severeSource["score"].get<int>() < 80 ||
      severeSource["category"] != "Highly Risky" ||
      severeSource["software_assessment"]["category_scores"]["source_domain"]
              .get<int>() < 90 ||
      severeSource["software_assessment"]["redirects"]["status"] !=
          "not_followed")
    throw std::runtime_error(
        "A deceptive source with a redirect parameter did not combine into a "
        "high risk score.");

  const J incompletePublisherPath = scan("", "https://blender.org/");
  if (incompletePublisherPath["source_status"] != "UNVERIFIED" ||
      incompletePublisherPath["score"].get<int>() < 61)
    throw std::runtime_error(
        "An incomplete reference match to a legitimate domain was treated as "
        "malicious.");

  const J publisherMismatch =
      scan("VLC Media Player", "https://www.videolan.org/vlc/",
           "Microsoft Corporation");
  if (publisherMismatch["score"].get<int>() < 61 ||
      publisherMismatch["score"].get<int>() > 100 ||
      publisherMismatch["category"] != "Highly Risky" ||
      !hasSoftwareSignal(publisherMismatch, "declared_publisher_mismatch"))
    throw std::runtime_error(
        "A confirmed publisher mismatch was missed or under-scored.");

  const J contradictory =
      scan("Blender", "https://www.blender.org/download/",
           "Microsoft Corporation");
  if (contradictory["source_status"] != "VERIFIED_OFFICIAL" ||
      contradictory["score"].get<int>() < 61 ||
      contradictory["score"].get<int>() > 100 ||
      contradictory["category"] != "Highly Risky" ||
      !hasSoftwareSignal(contradictory, "declared_publisher_mismatch") ||
      contradictory["software_assessment"]["positive_evidence"].empty())
    throw std::runtime_error(
        "Contradictory source and publisher evidence was not kept distinct.");

  const J missingOptional = scan("", "https://www.blender.org/download/");
  if (missingOptional["source_status"] != "VERIFIED_OFFICIAL" ||
      missingOptional["score"].get<int>() != 0 ||
      !missingOptional["software_assessment"]["completeness"]
           ["missing_evidence"]
           .is_array())
    throw std::runtime_error(
        "Missing optional product or publisher fields were not reported as "
        "incomplete.");

  const J missingPublisher =
      scan("Unknown Utility", "https://utility.example.test/download", "");
  if (missingPublisher["source_verification"]["status"] != "UNVERIFIED" ||
      missingPublisher["source_reference"].is_object() ||
      missingPublisher["score"].get<int>() < 61)
    throw std::runtime_error(
        "A missing publisher was treated as verification or risk evidence.");

  bool emptySoftwareRejected = false;
  try {
    scan("");
  } catch (const Problem &error) {
    emptySoftwareRejected = error.status == 400;
  }
  if (!emptySoftwareRejected)
    throw std::runtime_error("An empty Software request received a Safe score.");

  if (!invalidSoftwareUrl("https://blender.org:99999/download"))
    throw std::runtime_error("An invalid URL port was accepted.");

  const J assessmentScores = severeSource["software_assessment"]["category_scores"];
  for (const auto &entry : assessmentScores.items())
    if (entry.value().get<int>() < 0 || entry.value().get<int>() > 100)
      throw std::runtime_error(
          "A Software risk dimension escaped the 0–100 range.");
  if (severeSource["score"] !=
      severeSource["software_assessment"]["weighted_score"] ||
      severeSource["software_assessment"]["threat_intelligence"]["status"] !=
          "not_configured")
    throw std::runtime_error(
        "Software weighted score or unavailable threat intelligence was "
        "reported incorrectly.");
  for (const J *report : {&severeSource, &publisherMismatch, &contradictory,
                            &blender, &novaEdit, &numericHost}) {
    const int score = report->at("score").get<int>();
    if (score < 0 || score > 100)
        throw std::runtime_error("A Software risk score escaped 0–100.");
  }
  for (const int score : {0, 35, 36, 60, 61, 100}) {
    const J boundary = softwareBoundaryReport(score);
    const S expected = score >= 61 ? "Highly Risky"
                         : score >= 36 ? "Be Cautious"
                                       : "Safe";
    if (boundary["score"] != score || boundary["category"] != expected)
        throw std::runtime_error(
            "Software score classification does not match the universal "
            "boundary bands.");
  }

  const J fakeMalwareFile = {
      {"notes", J::array()},
      {"file_assessment",
       {{"file_name", "vlc.exe"},
        {"size_bytes", 4096},
        {"sha256", S(64, 'a')},
        {"file_type", "Windows PE executable"},
        {"extension", "exe"},
        {"extension_mismatch", false},
        {"static_indicators", J::array()},
        {"scanner_status", "detected"},
        {"scanner_engine", "test local scanner"},
        {"authenticode",
         {{"status", "invalid_signature"},
          {"signer", "Unrelated Publisher"},
          {"message", "The embedded signature digest does not match the file."}}}}}};
  const J combinedFile =
      scoreSoftwareReport(officialVersioned,
                          officialVersioned["software_assessment"]["signals"],
                          officialVersioned["software_assessment"]
                                           ["product_context"],
                          fakeMalwareFile);
  if (combinedFile["category"] != "Highly Risky" ||
      combinedFile["software_assessment"]["category_scores"]
                   ["file_authenticity"] != 100 ||
      combinedFile["software_assessment"]["category_scores"]
                   ["file_characteristics"] != 100 ||
      combinedFile["sha256"] != S(64, 'a') ||
      combinedFile["file_name"] != "vlc.exe" ||
      combinedFile["software_assessment"]["threat_intelligence"]
                   ["file_uploaded"] != false)
    throw std::runtime_error(
        "File authenticity and local detection evidence were not combined.");

  if (!invalidSoftwareUrl("ftp://example.org/download") ||
      !invalidSoftwareUrl("https://bad host"))
    throw std::runtime_error("Malformed or unsupported software URLs passed.");

  const J legitimateOtp =
      scanSms("ICICI Bank: Your OTP is 123456. Do not share it.");
  if (legitimateOtp["category"] != "Safe" ||
      legitimateOtp["score"].get<int>() >= 20 ||
      hasSmsSignal(legitimateOtp, "credential_sharing_request") ||
      legitimateOtp.contains("trust_score") ||
      !smsClassificationConsistent(legitimateOtp))
    throw std::runtime_error("A legitimate OTP notification was over-scored.");
  bool emptySmsRejected = false;
  try {
    scanSms("");
  } catch (const Problem &error) {
    emptySmsRejected = error.status == 400;
  }
  if (!emptySmsRejected)
    throw std::runtime_error("An empty SMS body was analyzed.");

  const J normalOtp = scanSms("Your OTP is 123456.");
  if (normalOtp["category"] != "Safe" ||
      hasSmsSignal(normalOtp, "credential_sharing_request"))
    throw std::runtime_error("An OTP notification was mistaken for a request.");

  const J harmlessLibrarySms = scanSms(
      "Hi! The library will remain open until 8 PM today. You can return your "
      "books at the front desk before closing. Thank you.");
  const J rewardSms = scanSms(
      "Congratulations! Your number has been selected for a ₹25,000 reward. "
      "Your reward is pending verification. Please verify your eligibility "
      "within 24 hours or your reward will expire.");
  const J rewardSmsWithLink = scanSms(
      "Congratulations! Your ₹25,000 reward is ready. Verification is pending "
      "and your claim expires today. Link included for testing: "
      "[https://reward-check.example.test/verify]"
      "(https://reward-check.example.test/verify)");
  if (harmlessLibrarySms["score"].get<int>() >= 36 ||
      harmlessLibrarySms["category"] != "Safe" ||
      rewardSms["score"].get<int>() < 36 ||
      !hasSmsSignal(rewardSms, "contextual_reward_claim") ||
      !hasSmsSignal(rewardSms, "reward_claim_or_verification_action") ||
      !hasSmsSignal(rewardSms, "urgency_or_threat") ||
      rewardSmsWithLink["score"].get<int>() <=
          rewardSms["score"].get<int>() ||
      !hasSmsSignal(rewardSmsWithLink, "unverified_reward_destination") ||
      rewardSmsWithLink["sms_assessment"]["links"]["found"] != 1)
    throw std::runtime_error(
        "A contextual reward SMS or its unverified verification link was "
        "missed or under-scored.");

  const J deadlineOnlySms =
      scanSms("Your appointment reminder: please respond within 24 hours.");
  const J ordinaryLinkedSms =
      scanSms("Library hours and returns: "
              "https://library.example.test/return-hours");
  const J unknownSenderOnlySms =
      scanSms("The community meeting starts at 5 PM.", "UNKNOWN-442");
  if (deadlineOnlySms["score"].get<int>() >= 36 ||
      deadlineOnlySms["category"] != "Safe" ||
      ordinaryLinkedSms["score"].get<int>() >= 36 ||
      ordinaryLinkedSms["category"] != "Safe" ||
      unknownSenderOnlySms["score"].get<int>() >= 36 ||
      unknownSenderOnlySms["category"] != "Safe")
    throw std::runtime_error(
        "A deadline, ordinary URL, or unknown sender alone was over-scored.");

  const J legitimateBankAlert =
      scanEmail("alerts@icicibank.com", "ICICI Bank debit alert",
                "Rs 500 was debited from your account ending 1234. If this "
                "wasn't you, contact the bank using the number on your card. "
                "Do not share any OTP.");
  if (legitimateBankAlert["score"].get<int>() >= 20 ||
      hasEmailSignal(legitimateBankAlert, "credential_request"))
    throw std::runtime_error(
        "A legitimate bank debit alert was treated as a credential request.");

  const J smsScam = scanSms(
      "ICICI Bank account suspended immediately. Send us your OTP to restore "
      "access at https://verify.example.xyz/login");
  if (smsScam["category"] != "Highly Risky" ||
      smsScam["score"].get<int>() < 61 ||
      !hasSmsSignal(smsScam, "credential_sharing_request") ||
      !hasSmsSignal(smsScam, "claimed_organization_domain_mismatch") ||
      smsScam.contains("trust_score"))
    throw std::runtime_error("An urgent OTP scam was not rated high risk.");

  const J multiActionSmsScam = scanSms(
      "ICICI Bank security alert: Your account access will be suspended "
      "immediately. To avoid permanent account restriction within 10 minutes, "
      "complete KYC, pay the pending security fee, and send us the "
      "verification code (OTP).");
  if (multiActionSmsScam["category"] != "Highly Risky" ||
      multiActionSmsScam["score"].get<int>() < 61 ||
      multiActionSmsScam["sms_assessment"]["sender"]["status"] !=
          "not_provided" ||
      !hasSmsSignal(multiActionSmsScam, "credential_sharing_request") ||
      !hasSmsSignal(multiActionSmsScam, "account_or_kyc_action") ||
      !hasSmsSignal(multiActionSmsScam, "payment_or_transfer_request") ||
      !hasSmsSignal(multiActionSmsScam, "urgency_or_threat"))
    throw std::runtime_error(
        "A multi-action bank impersonation message was under-scored or "
        "missed independent requests.");

  const J safetyWarning =
      scanSms("Your account will not be suspended. Never share your OTP and "
              "do not pay an unexpected fee.");
  if (hasSmsSignal(safetyWarning, "credential_sharing_request") ||
      hasSmsSignal(safetyWarning, "payment_or_transfer_request") ||
      hasSmsSignal(safetyWarning, "urgency_or_threat"))
    throw std::runtime_error(
        "Negated safety guidance was mistaken for a request or threat.");

  const J contradictorySms =
      scanSms("Never share your OTP. Send us your OTP now. Never pay the fee. "
              "Pay your bill now.");
  if (!hasSmsSignal(contradictorySms, "credential_sharing_request") ||
      !hasSmsSignal(contradictorySms, "payment_or_transfer_request"))
    throw std::runtime_error(
        "Earlier negated guidance suppressed later positive requests.");

  const J timedKycThreat =
      scanSms("Your bank account access will be suspended unless you complete "
              "KYC within 10 minutes.");
  if (!hasSmsSignal(timedKycThreat, "urgency_or_threat") ||
      !hasSmsSignal(timedKycThreat, "account_or_kyc_action") ||
      timedKycThreat["score"].get<int>() < 45)
    throw std::runtime_error(
        "A numeric deadline paired with account suspension and a KYC request "
        "was missed.");

  const J hiddenCharacterScam = scanSms(
      "ICICI Bank acc\u200bount suspended immediately. Send us your OTP.");
  if (hiddenCharacterScam["score"].get<int>() < 61)
    throw std::runtime_error("Hidden Unicode spacing bypassed SMS detection.");

  const J hinglishScam =
      scanSms("Aapka account turant band hoga, apna OTP bhejo abhi.");
  if (hinglishScam["score"].get<int>() < 61)
    throw std::runtime_error("A Hinglish OTP request with urgency was missed.");

  const J senderUnverified =
      scanSms("ICICI Bank: Your account ending 1234 was debited Rs 500.",
              "ICICI-BANK");
  if (senderUnverified["category"] != "Safe" ||
      senderUnverified["sms_assessment"]["sender"]["status"] != "unverified" ||
      senderUnverified["score"].get<int>() >= 36)
    throw std::runtime_error("An unregistered brand-like sender was trusted.");

  const J claimedDomainMismatch = scanSms(
      "ICICI Bank: View your statement at https://fake.example.net/statement");
  if (!smsClassificationConsistent(claimedDomainMismatch) ||
      !hasSmsSignal(claimedDomainMismatch,
                    "claimed_organization_domain_mismatch") ||
      claimedDomainMismatch["sms_assessment"]["links"]["items"][0]["host"] !=
          "fake.example.net")
    throw std::runtime_error("An unrelated claimed-bank link was not flagged.");
  const J matchingOfficialDomain =
      scanSms("ICICI Bank: View your statement at "
              "https://www.icicibank.com/statements");
  if (matchingOfficialDomain["sms_assessment"]["positive_evidence"].empty() ||
      hasSmsSignal(matchingOfficialDomain,
                   "claimed_organization_domain_mismatch"))
    throw std::runtime_error(
        "A configured official domain was not described as supporting evidence.");

  const J deliveryPayment =
      scanSms("Your parcel delivery failed. Pay the delivery fee here.");
  if (!smsClassificationConsistent(deliveryPayment) ||
      !hasSmsSignal(deliveryPayment, "delivery_fee_lure"))
    throw std::runtime_error("A delivery payment request was not flagged.");

  const J pendingPayment =
      scanSms("Your payment request is pending. Complete the pending "
              "transaction immediately or your account access will be suspended.");
  if (pendingPayment["category"] != "Highly Risky" ||
      pendingPayment["score"].get<int>() < 61 ||
      !hasSmsSignal(pendingPayment, "payment_or_transfer_request") ||
      !hasSmsSignal(pendingPayment, "urgency_or_threat"))
    throw std::runtime_error(
        "A pending-payment request with account suspension was under-scored: " +
        pendingPayment.dump());

  const J combinedAccountPayment =
      scanSms("URGENT: Your bank account access has been restricted. "
              "A pending payment of Rs. 4,999 requires confirmation today. "
              "Failure to complete verification may result in permanent "
              "account suspension. Verify your account immediately to avoid "
              "further action.");
  if (combinedAccountPayment["category"] != "Highly Risky" ||
      combinedAccountPayment["score"].get<int>() < 61 ||
      !hasSmsSignal(combinedAccountPayment, "payment_or_transfer_request") ||
      !hasSmsSignal(combinedAccountPayment, "account_or_kyc_action") ||
      !hasSmsSignal(combinedAccountPayment, "urgency_or_threat"))
    throw std::runtime_error(
        "The combined account restriction and payment threat was under-scored: " +
        combinedAccountPayment.dump());

  const J compromiseThreat =
      scanSms("Account compromise detected. Account access is restricted "
              "and will be permanently suspended today. Complete the security "
              "review and pay the pending security fee. Verify immediately.");
  if (compromiseThreat["category"] != "Highly Risky" ||
      compromiseThreat["score"].get<int>() < 61 ||
      !hasSmsSignal(compromiseThreat, "payment_or_transfer_request") ||
      !hasSmsSignal(compromiseThreat, "account_or_kyc_action") ||
      !hasSmsSignal(compromiseThreat, "urgency_or_threat"))
    throw std::runtime_error(
        "Account compromise, restriction, verification, and payment signals "
        "did not combine into a high-risk result.");

  const J normalConversation =
      scanSms("Urgent, please send me the meeting notes before 5.");
  if (normalConversation["category"] != "Safe" ||
      normalConversation["score"].get<int>() >= 36)
    throw std::runtime_error(
        "Urgency in a normal conversation was treated as a scam.");

  const J informationalSmsPayment =
      scanSms("ICICI Bank: Rs 500 was debited from your account. "
              "Your payment is complete. Never share your OTP.");
  if (informationalSmsPayment["category"] != "Safe" ||
      hasSmsSignal(informationalSmsPayment, "payment_or_transfer_request") ||
      hasSmsSignal(informationalSmsPayment, "credential_sharing_request"))
    throw std::runtime_error(
        "Informational payment and bank terms were mistaken for requests.");

  const J safeDelivery =
      scanSms("Your parcel is out for delivery tomorrow. Track it in the "
              "carrier's app.");
  if (safeDelivery["category"] != "Safe" ||
      hasSmsSignal(safeDelivery, "delivery_fee_lure"))
    throw std::runtime_error(
        "A routine delivery update was treated as a fee scam.");

  const J deliveryLinkScam = scanSms(
      "Your parcel delivery failed. Pay the delivery fee now to avoid return: "
      "https://track-parcel.example.xyz/pay");
  if (deliveryLinkScam["score"].get<int>() < 36 ||
      !smsClassificationConsistent(deliveryLinkScam) ||
      !hasSmsSignal(deliveryLinkScam, "delivery_fee_link"))
    throw std::runtime_error(
        "A delivery fee request with an unfamiliar link was under-scored.");
  const J remoteAppScam =
      scanSms("Your bank account is blocked. Install AnyDesk now to restore "
              "access and process your refund.");
  if (remoteAppScam["category"] != "Highly Risky" ||
      !hasSmsSignal(remoteAppScam, "app_install_request") ||
      !hasSmsSignal(remoteAppScam, "remote_access_financial_lure"))
    throw std::runtime_error(
        "A remote-access app request in a banking context was missed.");

  const J shortened = scanSms(
      "Pay the fee at https://bit.ly/parcel-123 to release your delivery.");
  if (!hasSmsSignal(shortened, "shortened_link") ||
      smsDimension(shortened, "link_destination") < 60)
    throw std::runtime_error("A shortened SMS link was not identified.");

  const J deceptiveLink = scanSms(
      "ICICI Bank: update your KYC at "
      "https://icicibank.com.example.net/verify");
  if (!hasSmsSignal(deceptiveLink,
                    "claimed_organization_domain_mismatch") ||
      deceptiveLink["sms_assessment"]["links"]["items"][0]["host"] !=
          "icicibank.com.example.net")
    throw std::runtime_error(
        "A deceptive subdomain was mistaken for the bank's official domain.");

  const J userInfoLink =
      scanSms("Open https://icicibank.com@attacker.example/login");
  if (!hasSmsSignal(userInfoLink, "url_userinfo") ||
      userInfoLink["sms_assessment"]["links"]["found"] != 1 ||
      userInfoLink["sms_assessment"]["links"]["items"][0]["host"] !=
          "attacker.example")
    throw std::runtime_error(
        "URL user information obscuring the true host was missed.");
  const J numericSmsHost = scanSms("Review this address http://192.0.2.10/login");
  if (!hasSmsSignal(numericSmsHost, "ip_host") ||
      numericSmsHost["sms_assessment"]["links"]["items"][0]["host"] !=
          "192.0.2.10")
    throw std::runtime_error("A numeric IP address in an SMS link was missed.");

  const J encodedLink =
      scanSms("Verify using https%3A%2F%2Fexample.net%2Flogin");
  if (!hasSmsSignal(encodedLink, "url_percent_encoded") ||
      encodedLink["sms_assessment"]["links"]["items"][0]["host"] !=
          "example.net")
    throw std::runtime_error("An encoded SMS URL was not analyzed.");

  const J ordinarySmsUrl =
      scanSms("Download details: https://example.net/download?file=app.apk&mirror=1.");
  if (ordinarySmsUrl["score"].get<int>() >= 20)
    throw std::runtime_error(
        "Ordinary slashes and query parameters raised SMS risk.");

  const J multipleLinks = scanSms(
      "Compare these pages https://first.example/a and (www.second.example/b).");
  if (multipleLinks["sms_assessment"]["links"]["found"] != 2 ||
      multipleLinks["sms_assessment"]["links"]["analyzed"] != 2)
    throw std::runtime_error("Multiple SMS link domains were not extracted.");

  const J redirectParameter =
      scanSms("Open https://example.net/go?redirect=https%3A%2F%2Fattacker.example");
  if (!hasSmsSignal(redirectParameter, "redirect_parameter") ||
      redirectParameter["sms_assessment"]["links"]["items"][0]
                       ["redirect_hosts"][0] != "attacker.example")
    throw std::runtime_error(
        "An explicit redirect destination was not inspected locally.");

  const J malformedLink = scanSms("Open this link https://[broken");
  if (malformedLink["sms_assessment"]["links"]["complete"] != false ||
      malformedLink["sms_assessment"]["completeness"]["score"].get<int>() >=
          100)
    throw std::runtime_error(
        "A malformed link was treated as fully analyzed or safe.");

  const J unsupportedLink = scanSms("Download at ftp://example.net/file");
  if (!hasSmsSignal(unsupportedLink, "unsupported_link_scheme") ||
      unsupportedLink["sms_assessment"]["links"]["complete"] != false)
    throw std::runtime_error(
        "An unsupported URL scheme was not reported as incomplete.");

  const J omittedSender = scanSms("Your account summary is ready.");
  if (omittedSender["sms_assessment"]["sender"]["status"] != "not_provided" ||
      omittedSender["sms_assessment"]["completeness"]["score"].get<int>() >=
          100 ||
      omittedSender["score"].get<int>() >= 20)
    throw std::runtime_error(
        "Missing sender metadata was confused with risk or full verification.");

  const J incompleteLink = scanSms(
      "Your bank account is restricted. Click the link to restore access.");
  if (incompleteLink["sms_assessment"]["links"]["complete"] != false ||
      incompleteLink["sms_assessment"]["completeness"]["missing_evidence"]
                  .dump()
                  .find("not included") == S::npos)
    throw std::runtime_error(
        "A referenced but omitted URL was treated as analyzed.");

  const J deterministicFirst = scanSms(
      "Account suspended immediately. Send us your OTP at "
      "https://bad.example.xyz/verify");
  const J deterministicSecond = scanSms(
      "Account suspended immediately. Send us your OTP at "
      "https://bad.example.xyz/verify");
  if (deterministicFirst != deterministicSecond)
    throw std::runtime_error("SMS scores are not deterministic.");

  const auto &smsScores =
      deterministicFirst["sms_assessment"]["category_scores"];
  for (const auto &entry : smsScores.items())
    if (entry.value().get<int>() < 0 || entry.value().get<int>() > 100)
      throw std::runtime_error("An SMS category score escaped 0–100.");
  const int expectedSmsScore =
      std::min(100, deterministicFirst["sms_assessment"]["weighted_score"]
                            .get<int>() +
                        deterministicFirst["sms_assessment"]
                            ["interaction_adjustment"]
                                .get<int>());
  if (deterministicFirst["score"].get<int>() != expectedSmsScore ||
      deterministicFirst["score"].get<int>() < 0 ||
      deterministicFirst["score"].get<int>() > 100 ||
      deterministicFirst["sms_assessment"]["weights"]["link_destination"] !=
          30 ||
      deterministicFirst["sms_assessment"]["weights"]
                        ["sender_impersonation"] != 25 ||
      deterministicFirst["sms_assessment"]["weights"]
                        ["requested_action_financial"] != 20 ||
      deterministicFirst["sms_assessment"]["weights"]["urgency_pressure"] !=
          15 ||
      deterministicFirst["sms_assessment"]["weights"]
                        ["context_suspiciousness"] != 10)
    throw std::runtime_error(
        "SMS score bounds, weighted dimensions, or configuration are invalid.");

  for (const J *report :
       {&legitimateOtp, &normalOtp, &harmlessLibrarySms, &rewardSms,
        &rewardSmsWithLink, &deadlineOnlySms, &ordinaryLinkedSms,
        &unknownSenderOnlySms, &smsScam, &multiActionSmsScam, &safetyWarning,
        &contradictorySms, &timedKycThreat, &hiddenCharacterScam, &hinglishScam,
        &senderUnverified, &claimedDomainMismatch, &matchingOfficialDomain,
        &deliveryPayment, &normalConversation, &informationalSmsPayment,
        &safeDelivery, &deliveryLinkScam, &remoteAppScam, &shortened,
        &deceptiveLink, &userInfoLink, &numericSmsHost, &encodedLink,
        &ordinarySmsUrl, &multipleLinks, &redirectParameter, &malformedLink,
        &unsupportedLink, &omittedSender, &incompleteLink, &deterministicFirst,
        &pendingPayment, &combinedAccountPayment, &compromiseThreat}) {
    const int score = report->at("score").get<int>();
    const int expectedScore =
        std::min(100, report->at("sms_assessment")
                          .at("weighted_score")
                          .get<int>() +
                          report->at("sms_assessment")
                              .at("interaction_adjustment")
                              .get<int>());
    if (score < 0 || score > 100 || score != expectedScore ||
        !smsClassificationConsistent(*report))
      throw std::runtime_error(
          "An SMS score was out of bounds, misaggregated, or classified "
          "inconsistently with the 0–35/36–60/61–100 bands.");
  }

  const S privateSender = "PRIVATE-HEADER-7788";
  const S privateMessage =
      "Your confidential case number ZX-9912 is ready.";
  const J privateReport = scanSms(privateMessage, privateSender);
  if (privateReport.dump().find(privateSender) != S::npos ||
      privateReport.dump().find(privateMessage) != S::npos)
    throw std::runtime_error(
        "The SMS response unexpectedly retained sender or full message text.");

  const J suspiciousDeliveryEmail =
      scanEmail("axa.weih@gmail.com",
                "URGENT: Your parcel #IN-884920 could not be delivered",
                "wecs go to www.akj.jask.com to claim");
  if (suspiciousDeliveryEmail["category"] != "Suspicious" ||
      suspiciousDeliveryEmail["score"].get<int>() < 45 ||
      !hasEmailSignal(suspiciousDeliveryEmail, "urgent_delivery_link"))
    throw std::runtime_error(
        "An urgent delivery email with a consumer sender and unrelated link "
        "was not rated cautiously: " + suspiciousDeliveryEmail.dump());

  const J emailDomainMismatch =
      scanEmail("alerts@icicibank.com", "ICICI Bank statement",
                "Your statement is ready at "
                "https://fake.example.net/statement");
  if (emailDomainMismatch["category"] != "Caution" ||
      emailDimension(emailDomainMismatch, "link_destination") < 85 ||
      !hasEmailSignal(emailDomainMismatch, "organization_link_mismatch"))
    throw std::runtime_error(
        "An email link outside the claimed bank's configured domains was not "
        "reported as a strong link signal: " + emailDomainMismatch.dump());

  const J legitimateEmailLink =
      scanEmail("alerts@icicibank.com", "ICICI Bank statement",
                "Your statement is ready at "
                "https://www.icicibank.com/statements.");
  if (legitimateEmailLink["category"] != "Low Risk" ||
      legitimateEmailLink["score"].get<int>() != 0 ||
      legitimateEmailLink.contains("trust_score"))
    throw std::runtime_error(
        "A known organization's official email link was flagged or a second "
        "email score was returned.");

  const J normalUrgentEmail =
      scanEmail("team@publisher.example", "Meeting reminder",
                "Please send the draft immediately so we can review it. No "
                "account, payment, or credential action is requested.");
  if (normalUrgentEmail["score"].get<int>() >= 20 ||
      normalUrgentEmail["category"] != "Low Risk")
    throw std::runtime_error(
        "Urgency without a risky request was treated as a dangerous email.");

  const S syntheticPrizeBody =
      "You were selected as a winner for a ₹50,000 prize reward. Claim the "
      "prize. Please verify your identity within 24 hours, or you will lose "
      "eligibility and the reward will be cancelled.";
  const J prizeWithoutLink =
      scanEmail("notify@unlisted-mail.example", "Prize claim",
                syntheticPrizeBody);
  const J prizeWithRiskyLink =
      scanEmail("notify@unlisted-mail.example", "Prize claim",
                syntheticPrizeBody +
                    " Verification: https://claim-reward.xyz/verify");
  if (prizeWithoutLink["category"] != "High risk" ||
      prizeWithoutLink["score"].get<int>() < 70 ||
      prizeWithRiskyLink["score"].get<int>() <=
          prizeWithoutLink["score"].get<int>() ||
      prizeWithRiskyLink["email_assessment"]["links"]["found"] != 1 ||
      hasEmailSignal(prizeWithRiskyLink, "pressure_financial_link") ||
      hasEmailSignal(prizeWithRiskyLink, "threat_sensitive_link"))
    throw std::runtime_error(
        "A contextual prize lure or its suspicious verification link was "
        "under-scored or counted twice: " +
        prizeWithRiskyLink.dump());
  for (const S &signal :
       Args{"contextual_prize_reward_claim", "prize_claim_action",
            "sensitive_data_request", "urgency_pressure",
            "unverified_sender_action"})
    if (!hasEmailSignal(prizeWithoutLink, signal))
      throw std::runtime_error("Prize-lure evidence was not explained: " +
                               signal);
  if (prizeWithoutLink["findings"].dump().find("Indicator strength") ==
          S::npos ||
      prizeWithoutLink["email_assessment"]["summary"].get<S>().find(
          "Independent evidence combinations") == S::npos)
    throw std::runtime_error(
        "Email findings or the combination adjustment omitted score "
        "explanations.");

  const J prizeWithoutDeadline =
      scanEmail("lottery@unlisted-mail.example", "Prize claim",
                "The winner was selected and can claim a reward of ₹2,000.");
  const J prizeWithVerification =
      scanEmail("lottery@unlisted-mail.example", "Prize claim",
                "The winner was selected and can claim a reward of ₹2,000 "
                "after you verify your identity.");
  if (prizeWithoutDeadline["score"].get<int>() < 20 ||
      prizeWithVerification["score"].get<int>() <=
          prizeWithoutDeadline["score"].get<int>())
    throw std::runtime_error(
        "Prize-claim and verification evidence were not distinguished.");

  const J unknownSenderHarmless =
      scanEmail("person@unlisted-mail.example", "Workshop reminder",
                "The workshop starts tomorrow. No action is needed.");
  const J emailMissingOptionalFields =
      scanEmail("", "", "This is an ordinary informational note.");
  const J ordinaryPromotion =
      scanEmail("offers@store.example", "Summer update",
                "Enter our summer giveaway. No winner has been selected and "
                "no claim or personal information is requested.");
  const J negatedVerification =
      scanEmail("security@service.example", "Security reminder",
                "We will never ask you to verify your identity or share a "
                "code.");
  const J negatedPrizeClaim =
      scanEmail("awareness@service.example", "Prize scam awareness",
                "Do not claim a prize from an unexpected email. We will "
                "never ask you to verify your identity.");
  if (unknownSenderHarmless["score"].get<int>() >= 20 ||
      emailMissingOptionalFields["score"].get<int>() != 0 ||
      emailMissingOptionalFields["category"] != "Low Risk" ||
      ordinaryPromotion["score"].get<int>() >= 20 ||
      emailDimension(negatedVerification,
                     "financial_sensitive_action") != 0 ||
      hasEmailSignal(negatedPrizeClaim, "contextual_prize_reward_claim"))
    throw std::runtime_error(
        "Unknown sender, ordinary promotion, or negated request was treated "
        "as a confirmed risk.");

  const J repeatedPrize =
      scanEmail("notify@unlisted-mail.example", "Prize claim",
                syntheticPrizeBody + " " + syntheticPrizeBody);
  if (repeatedPrize["score"] != prizeWithoutLink["score"])
    throw std::runtime_error(
        "Repeated wording inflated the same email risk evidence.");

  bool malformedEmailSenderRejected = false;
  try {
    scanEmail("not-an-address", "Notice", "No action is required.");
  } catch (const Problem &error) {
    malformedEmailSenderRejected = error.status == 400;
  }
  if (!malformedEmailSenderRejected)
    throw std::runtime_error(
        "A malformed email sender was not rejected explicitly.");

  const J informationalPayment =
      scanEmail("billing@shop.example", "Payment received",
                "Your payment of Rs 999 was received. No further action is "
                "required.");
  if (informationalPayment["score"].get<int>() >= 20 ||
      emailDimension(informationalPayment, "financial_sensitive_action") != 0)
    throw std::runtime_error(
        "A passive payment receipt was mistaken for a payment request.");

  const J legitimateEmailOtp =
      scanEmail("alerts@icicibank.com", "ICICI Bank login code",
                "Your OTP is 123456. Do not share it with anyone.");
  const J requestedOtp =
      scanEmail("alerts@icicibank.com", "ICICI Bank account verification",
                "Send us your OTP to verify your account.");
  if (emailDimension(legitimateEmailOtp, "financial_sensitive_action") != 0 ||
      emailDimension(requestedOtp, "financial_sensitive_action") < 95 ||
      requestedOtp["score"].get<int>() < 20)
    throw std::runtime_error(
        "An informational OTP was not distinguished from a request to share "
        "one.");

  const J legitimateDelivery =
      scanEmail("tracking@carrier.example", "Delivery update",
                "Your parcel is scheduled to arrive tomorrow. Track it at "
                "https://carrier.example/track.");
  if (legitimateDelivery["score"].get<int>() >= 20 ||
      hasEmailSignal(legitimateDelivery, "urgent_delivery_link"))
    throw std::runtime_error(
        "A routine delivery update was treated as a scam.");

  const J renewalScam =
      scanEmail("billing@auto-renewal-service.example.org",
                "URGENT: Payment Receipt: Rs. 14,999 debited for Annual Plan",
                "Your subscription has been automatically renewed. If you did "
                "not authorize this charge, submit a cancellation request "
                "immediately at "
                "[http://refund-portal.example.org](http://refund-portal.example.org)");
  if (renewalScam["category"] != "High risk" ||
      renewalScam["score"].get<int>() < 70 ||
      renewalScam["email_assessment"]["links"]["found"] != 1 ||
      renewalScam["email_assessment"]["links"]["items"][0]["host"] !=
          "refund-portal.example.org")
    throw std::runtime_error(
        "The renewal/refund lure or its Markdown URL destination was not "
        "analyzed as high risk: " +
        renewalScam.dump());

  const J extractedEmailLinks =
      scanEmail("alerts@icicibank.com", "ICICI Bank statement",
                "Read https://www.icicibank.com/statement, see "
                "[www.icicibank.com](https://evil.example/login), and "
                "<a href=\"https://evil.example/confirm\">icicibank.com</a>");
  if (extractedEmailLinks["email_assessment"]["links"]["found"] != 3 ||
      !hasEmailSignal(extractedEmailLinks, "visible_destination_mismatch") ||
      !hasEmailSignal(extractedEmailLinks, "organization_link_mismatch"))
    throw std::runtime_error(
        "Markdown, HTML, and plain-text destinations were not analyzed "
        "individually: " +
        extractedEmailLinks.dump());

  const J punctuationLinks =
      scanEmail("", "", "Links: (https://first.example/path_(app)). Then "
                         "https://second.example/a?x=1&y=2, done.");
  if (punctuationLinks["email_assessment"]["links"]["found"] != 2 ||
      punctuationLinks["email_assessment"]["links"]["analyzed"] != 2)
    throw std::runtime_error(
        "URLs surrounded by ordinary punctuation were not normalized: " +
        punctuationLinks.dump());

  const J ordinaryEncodedQuery =
      scanEmail("sender@example.net", "Notice",
                "Reference: https://example.net/path?token=a%20b");
  if (emailDimension(ordinaryEncodedQuery, "link_destination") != 0)
    throw std::runtime_error(
        "Ordinary percent encoding in a query string raised link risk.");
  const J encodedHostname =
      scanEmail("sender@example.net", "Notice",
                "Reference: https://example%2enet/path");
  if (emailDimension(encodedHostname, "link_destination") < 60)
    throw std::runtime_error(
        "Percent-encoded hostname characters were not reported.");

  const J unsupportedEmailScheme =
      scanEmail("sender@example.net", "Notice", "Open ftp://files.example.net/app");
  if (unsupportedEmailScheme["email_assessment"]["links"]["items"][0]
            ["status"] != "unsupported_scheme" ||
      !hasEmailSignal(unsupportedEmailScheme, "unsupported_link_scheme"))
    throw std::runtime_error(
        "An unsupported email link scheme was not reported.");

  const J emailLookalike =
      scanEmail("", "Microsoft account notice",
                "Review https://microsoft.com.example.net/login");
  if (!hasEmailSignal(emailLookalike, "url_brand_lookalike"))
    throw std::runtime_error(
        "A deceptive hostname containing a configured publisher domain was "
        "not reported.");

  const J malformedEmailLink =
      scanEmail("sender@example.net", "Notice",
                "Open [this link](http://bad host");
  const J completeEmail =
      scanEmail("sender@example.net", "Notice", "No action is required.");
  if (malformedEmailLink["email_assessment"]["links"]["complete"] != false ||
      malformedEmailLink["email_assessment"]["confidence"]["complete"] !=
          false ||
      malformedEmailLink["email_assessment"]["confidence"]["score"].get<int>() >=
          completeEmail["email_assessment"]["confidence"]["score"].get<int>())
    throw std::runtime_error(
        "A malformed link was treated as safe or omitted from completeness.");

  const S passingHeaders =
      "From: ICICI Bank <alerts@icicibank.com>\r\n"
      "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\r\n";
  const S failingHeaders =
      "From: ICICI Bank <alerts@icicibank.com>\r\n"
      "Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\r\n";
  const J headersPass =
      scanEmail("", "ICICI Bank statement", "No action is required.",
                passingHeaders);
  const J headersFail =
      scanEmail("", "ICICI Bank statement", "No action is required.",
                failingHeaders);
  if (headersPass["score"].get<int>() != 0 ||
      headersPass["email_assessment"]["positive_evidence"].empty() ||
      headersPass["email_assessment"]["positive_evidence"].dump().find(
          "not independently verified") == S::npos ||
      emailDimension(headersFail, "sender_authenticity") <= 0 ||
      headersFail["score"].get<int>() <= headersPass["score"].get<int>())
    throw std::runtime_error(
        "Supplied authentication results were not reported separately from "
        "independent verification.");

  const J combinedScam =
      scanEmail("security@outlook.com",
                "ICICI Bank account suspended immediately",
                "ICICI Bank account suspended. Send us your OTP to restore "
                "access at https://icici-login.example.net/verify");
  if (combinedScam["category"] != "High risk" ||
      combinedScam["score"].get<int>() < 70)
    throw std::runtime_error(
        "Independent urgency, credential, sender, and link signals did not "
        "corroborate: " +
        combinedScam.dump());
  const J configuredWeights =
      combinedScam["email_assessment"]["weights"];
  if (configuredWeights["urgency_manipulation"] != 20 ||
      configuredWeights["link_destination"] != 25 ||
      configuredWeights["sender_authenticity"] != 15 ||
      configuredWeights["financial_sensitive_action"] != 25 ||
      configuredWeights["content_suspiciousness"] != 15)
    throw std::runtime_error(
        "The configured email scoring weights differ from the requested model.");

  const J recognizedSenderScam =
      scanEmail("alerts@icicibank.com",
                "ICICI Bank account suspended immediately",
                "Send us your OTP to restore access at "
                "https://icici-login.example.net/verify");
  if (recognizedSenderScam["category"] != "High risk" ||
      recognizedSenderScam["score"].get<int>() < 70 ||
      recognizedSenderScam["email_assessment"]["positive_evidence"].empty())
    throw std::runtime_error(
        "A recognized sender overrode strong scam signals or was not reported "
        "as heuristic evidence.");

  const J missingSenderScam =
      scanEmail("", "ICICI Bank account suspended immediately",
                "Send us your OTP to restore access at "
                "https://icici-login.example.net/verify");
  if (missingSenderScam["category"] != "High risk" ||
      missingSenderScam["email_assessment"]["confidence"]["missing_evidence"]
              .dump()
              .find("No sender address") == S::npos)
    throw std::runtime_error(
        "A message without a sender was not analyzed or its evidence gap was "
        "hidden.");

  const J repeatedEmail =
      scanEmail("team@publisher.example", "Meeting reminder",
                "Please send the draft immediately so we can review it. No "
                "account, payment, or credential action is requested.");
  if (normalUrgentEmail != repeatedEmail)
    throw std::runtime_error("Email scores were not deterministic.");

  for (const J *report : {&normalUrgentEmail, &prizeWithoutLink,
                          &prizeWithRiskyLink, &prizeWithoutDeadline,
                          &prizeWithVerification, &unknownSenderHarmless,
                          &emailMissingOptionalFields, &ordinaryPromotion,
                          &negatedVerification, &negatedPrizeClaim,
                          &repeatedPrize,
                          &informationalPayment,
                          &legitimateEmailOtp, &requestedOtp, &renewalScam,
                          &extractedEmailLinks, &punctuationLinks,
                          &ordinaryEncodedQuery, &encodedHostname,
                          &unsupportedEmailScheme, &emailLookalike,
                          &malformedEmailLink, &headersPass, &headersFail,
                          &combinedScam, &legitimateBankAlert,
                          &recognizedSenderScam, &missingSenderScam}) {
    const int score = report->at("score").get<int>();
    if (score < 0 || score > 100)
      throw std::runtime_error("Email overall score escaped 0–100.");
    const int expectedScore = std::min(
        100, report->at("email_assessment").at("weighted_score").get<int>() +
                 report->at("email_assessment")
                     .at("interaction_adjustment")
                     .get<int>());
    if (score != expectedScore)
      throw std::runtime_error(
          "Email overall score did not match its weighted and interaction "
          "components.");
    for (const S &key :
         Args{"urgency_manipulation", "link_destination",
              "sender_authenticity", "financial_sensitive_action",
              "content_suspiciousness"}) {
      const int value = emailDimension(*report, key);
      if (value < 0 || value > 100)
        throw std::runtime_error("Email category score escaped 0–100.");
    }
  }
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
