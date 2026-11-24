#include "software_analyzer.h"

#include "software_risk_config.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <vector>

namespace {
using SignalFamilies = std::map<S, std::map<S, int>>;

static int bounded(int score) {
  return std::max(0, std::min(100, score));
}

static int familyScore(const std::map<S, int> &families) {
  double remaining = 1.0;
  for (const auto &family : families)
    remaining *= 1.0 - bounded(family.second) / 100.0;
  return bounded(static_cast<int>(std::lround((1.0 - remaining) * 100.0)));
}

static S severityFor(int strength) {
  return strength >= 85   ? "Critical"
         : strength >= 65 ? "High"
         : strength >= 40 ? "Moderate"
         : strength >= 20 ? "Low"
                          : "Observation";
}

static void addSignal(J &signals, SignalFamilies &families, const S &id,
                      const S &name, const S &category, const S &family,
                      int strength, int confidence, const S &explanation,
                      const S &evidence, const S &verification,
                      const S &detectionMethod) {
  const int score = bounded(strength);
  if (score > 0) {
    int &familyStrength = families[category][family];
    familyStrength = std::max(familyStrength, score);
  }
  signals.push_back({{"id", id},
                     {"name", name},
                     {"category", category},
                     {"family", family},
                     {"severity", severityFor(score)},
                     {"text", explanation},
                     {"evidence", evidence},
                     {"score", score},
                     {"confidence", bounded(confidence)},
                     {"verification_status", verification},
                     {"detection_method", detectionMethod}});
}

static S riskCategory(int score) {
  if (score >= software_risk::config::HighRiskThreshold)
    return "Highly Risky";
  if (score >= software_risk::config::CautionThreshold)
    return "Be Cautious";
  return "Safe";
}

static S completenessLabel(int score) {
  return score >= 80 ? "Strong coverage"
         : score >= 50 ? "Partial coverage"
         : score > 0   ? "Limited coverage"
                       : "No applicable evidence";
}

static S normalizedPublisher(S value) {
  S result;
  for (unsigned char c : value)
    if (std::isalnum(c))
      result += static_cast<char>(std::tolower(c));
  static const Args suffixes = {"incorporated", "corporation", "company",
                                "limited", "inc", "corp", "ltd", "llc",
                                "plc"};
  bool removed = true;
  while (removed) {
    removed = false;
    for (const S &suffix : suffixes)
      if (result.size() > suffix.size() &&
          result.compare(result.size() - suffix.size(), suffix.size(),
                         suffix) == 0) {
        result.erase(result.size() - suffix.size());
        removed = true;
        break;
      }
  }
  return result;
}

static bool publisherMatches(const S &signer, const J &knownPublishers) {
  if (!knownPublishers.is_array())
    return false;
  const S normalizedSigner = normalizedPublisher(signer);
  if (normalizedSigner.empty())
    return false;
  for (const auto &publisher : knownPublishers) {
    if (!publisher.is_string())
      continue;
    const S expected = normalizedPublisher(publisher.get<S>());
    if (!expected.empty() && normalizedSigner == expected)
      return true;
  }
  return false;
}

static int weightedScore(const std::map<S, int> &scores,
                         const std::map<S, int> &weights) {
  int totalWeight = 0;
  long weightedTotal = 0;
  for (const auto &entry : weights) {
    if (entry.second <= 0)
      continue;
    weightedTotal += static_cast<long>(bounded(scores.at(entry.first))) *
                     entry.second;
    totalWeight += entry.second;
  }
  if (totalWeight == 0)
    return 0;
  return bounded(static_cast<int>(std::lround(
      static_cast<double>(weightedTotal) / totalWeight)));
}
} // namespace

J scoreSoftwareReport(J report, const J &sourceSignals, const J &context,
                      const J &fileReport) {
  J signals = J::array();
  SignalFamilies families;
  if (sourceSignals.is_array()) {
    for (const auto &signal : sourceSignals) {
      if (signal.is_object()) {
        signals.push_back(signal);
        const S category = signal.value("category", S());
        const S family = signal.value("family", S("source_signal"));
        const int strength = bounded(signal.value("score", 0));
        if (strength > 0) {
          int &stored = families[category][family];
          stored = std::max(stored, strength);
        }
      }
    }
  }

  std::vector<S> positiveEvidence;
  J limitations = J::array();
  J file = fileReport.is_object() ? fileReport.value("file_assessment", J())
                                  : J();
  const bool hasFile = file.is_object();
  const bool hasSource = report.value("hostname", S()).size() > 0;
  const S product = context.value("product", S());
  const S declaredPublisher = context.value("declared_publisher", S());
  const J knownPublishers = context.value("known_publishers", J::array());
  const bool knownProduct = !product.empty();
  const bool publisherCompared = knownProduct && !declaredPublisher.empty();
  const S fileSigner =
      hasFile ? file.value("authenticode", J::object()).value("signer", S())
              : S();
  const bool publisherComparisonAvailable =
      knownProduct && (publisherCompared || !fileSigner.empty());
  const bool hasRedirectSignal =
      sourceSignals.is_array() &&
      std::any_of(sourceSignals.begin(), sourceSignals.end(),
                  [](const J &signal) {
                    return signal.is_object() &&
                           signal.value("category", S()) ==
                               "redirect_destination";
                  });

  if (hasFile) {
    const S scannerStatus = file.value("scanner_status", "unavailable");
    const S scannerEngine = file.value("scanner_engine", "unknown local scanner");
    if (scannerStatus == "detected") {
      addSignal(signals, families, "local_malware_detection",
                "Local antivirus detection", "file_characteristics",
                "antivirus_verdict", 100, 98,
                "A configured local antimalware engine reported a detection.",
                scannerEngine + " reported a detection.",
                "local_engine_result", "Local antivirus provider");
    } else if (scannerStatus == "policy_blocked") {
      addSignal(signals, families, "local_antimalware_policy_block",
                "Local antimalware policy block", "file_characteristics",
                "antivirus_verdict", 78, 93,
                "The local Windows antimalware provider blocked the content "
                "under its configured policy.",
                scannerEngine + " reported a policy block.",
                "local_engine_result", "Windows antimalware provider");
    } else if (scannerStatus == "no_detection") {
      positiveEvidence.push_back(
          "The " + scannerEngine +
          " completed and reported no detection. This is limited evidence, "
          "not proof that the file is safe.");
    } else {
      limitations.push_back(
          "No local antivirus verdict was available for the selected file.");
    }

    if (file.value("extension_mismatch", false)) {
      addSignal(signals, families, "file_type_extension_mismatch",
                "File type does not match its extension",
                "file_characteristics", "format_mismatch", 78, 96,
                "The file header conflicts with its filename extension.",
                file.value("file_type", S("unknown")) + " content with ." +
                    file.value("extension", S()) + " extension",
                "verified_from_file_bytes", "File header inspection");
    }
    if (file.contains("static_indicators") &&
        file["static_indicators"].is_array()) {
      for (const auto &indicator : file["static_indicators"]) {
        if (!indicator.is_object())
          continue;
        addSignal(
            signals, families, indicator.value("id", S("static_indicator")),
            indicator.value("name", S("Static file indicator")),
            "file_characteristics",
            indicator.value("family", S("static_content")),
            indicator.value("strength", 0), indicator.value("confidence", 70),
            indicator.value("explanation", S()),
            indicator.value("evidence", S()),
            indicator.value("verification_status", S("heuristic")),
            "Static file inspection");
      }
    }

    const J signature = file.value("authenticode", J::object());
    const S signatureStatus = signature.value("status", "unavailable");
    const S signer = signature.value("signer", S());
    if (signatureStatus == "valid") {
      positiveEvidence.push_back(
          signer.empty() ? "The embedded Authenticode signature validated "
                           "against the local Windows trust policy."
                         : "The embedded Authenticode signature validated "
                           "against the local Windows trust policy; signer: " +
                               signer + ".");
    } else if (signatureStatus == "unsigned") {
      addSignal(signals, families, "unsigned_executable",
                "No Authenticode signature found", "file_authenticity",
                "signature_status", 22, 96,
                "No embedded Authenticode signature was found. Unsigned "
                "software can be legitimate; this is not proof of malware.",
                file.value("file_type", S("file")) +
                    " has no embedded signature",
                "verified_from_file_bytes", "Windows Authenticode verifier");
    } else if (signatureStatus == "invalid_signature" ||
               signatureStatus == "revoked" ||
               signatureStatus == "distrusted") {
      addSignal(signals, families, "invalid_authenticode_signature",
                "Authenticode signature failed verification",
                "file_authenticity", "signature_integrity", 100, 98,
                "The embedded Authenticode signature failed the local "
                "integrity or trust check.",
                signature.value("message", signatureStatus),
                "local_signature_verification",
                "Windows Authenticode verifier");
    } else if (signatureStatus == "present_untrusted") {
      addSignal(signals, families, "untrusted_authenticode_signer",
                "Signature present but signer is not trusted",
                "file_authenticity", "signature_trust", 68, 87,
                "A signature is present, but Windows could not establish "
                "trust for its signer using cached local trust data.",
                signature.value("message", signatureStatus),
                "local_signature_verification",
                "Windows Authenticode verifier");
    } else if (signatureStatus == "verification_unavailable") {
      limitations.push_back(
          "Authenticode verification could not complete; signature status "
          "is unknown, not unsigned.");
    } else if (signatureStatus == "not_applicable") {
      limitations.push_back(
          "Authenticode signing does not apply to the detected file type.");
    } else {
      limitations.push_back(
          "Authenticode verification is unavailable on this platform or for "
          "this file type.");
    }

    if (!signer.empty() && knownProduct) {
      if (publisherMatches(signer, knownPublishers)) {
        positiveEvidence.push_back(
            "The certificate signer name is consistent with the configured "
            "publisher reference for " +
            product + "; this comparison does not authenticate the "
                      "download source.");
      } else {
        addSignal(signals, families, "signer_product_mismatch",
                  "File signer differs from the listed product publisher",
                  "publisher_consistency", "signer_publisher_mismatch", 86,
                  80,
                  "The signer name in the file certificate does not match "
                  "the configured publisher names for this product.",
                  signer + " vs " +
                      (declaredPublisher.empty() ? product
                                                 : declaredPublisher),
                  "heuristic_certificate_name_comparison",
                  "Certificate signer name");
      }
    }

    if (!file.value("sha256", S()).empty()) {
      report["sha256"] = file["sha256"];
      report["file_size_bytes"] = file.value("size_bytes", 0);
      report["file_type"] = file.value("file_type", S());
      report["file_name"] = file.value("file_name", S());
    }
  } else {
    limitations.push_back(
        "No downloaded file was supplied; file hash, file type, antivirus, "
        "and signature checks were not performed.");
  }

  S sourceStatus = report.value("source_status", S("UNVERIFIED"));
  if (sourceStatus == "recognized")
    sourceStatus = "VERIFIED_OFFICIAL";
  else if (sourceStatus == "known_legitimate" ||
           sourceStatus == "unverified")
    sourceStatus = "UNVERIFIED";
  if (!hasSource)
    limitations.push_back(
        "No download URL or hostname was supplied; source identity could not "
        "be compared.");
  else if (sourceStatus == "VERIFIED_OFFICIAL")
    positiveEvidence.push_back(
        "The hostname and applicable path match a configured local "
        "official-source reference. The site was not opened, and this does "
        "not verify the downloaded file or every link on that site.");
  else if (sourceStatus == "SUSPICIOUS")
    limitations.push_back(
        "URL or product/source inconsistencies were detected. The submitted "
        "source is not verified and should not be used for a download.");
  else
    limitations.push_back(
        hasSource
            ? "No applicable official-source reference established this "
              "address as authentic. It is unverified, not confirmed "
              "malicious."
            : "No download URL or hostname was supplied; source authenticity "
              "could not be established.");

  if (!knownProduct || (declaredPublisher.empty() && fileSigner.empty()))
    limitations.push_back(
        "Publisher identity could not be compared with a known product "
        "reference.");
  else if (publisherCompared &&
           publisherMatches(declaredPublisher, knownPublishers))
    positiveEvidence.push_back(
        "The declared publisher matches the configured product reference; "
        "this text comparison does not authenticate the file.");
  if (fileReport.is_object() && !fileReport.value("notes", J()).empty()) {
    for (const auto &note : fileReport["notes"])
      if (note.is_string())
        report["notes"].push_back(note.get<S>());
  }

  std::map<S, int> scores = {
      {"source_domain", 0},
      {"file_authenticity", 0},
      {"file_characteristics", 0},
      {"redirect_destination", 0},
      {"threat_intelligence", 0},
      {"publisher_consistency", 0}};
  for (const auto &category : families)
    if (scores.count(category.first))
      scores[category.first] = familyScore(category.second);
  const bool publisherEvidenceAvailable =
      publisherComparisonAvailable || scores["publisher_consistency"] > 0;

  std::map<S, int> weights;
  const S fileSignatureStatus =
      hasFile ? file.value("authenticode", J::object())
                    .value("status", S("unknown"))
              : S();
  const bool signatureChecked =
      fileSignatureStatus == "valid" || fileSignatureStatus == "unsigned" ||
      fileSignatureStatus == "invalid_signature" ||
      fileSignatureStatus == "revoked" ||
      fileSignatureStatus == "distrusted" ||
      fileSignatureStatus == "present_untrusted";
  J dimensionStatus = {
      {"source_domain",
       {{"status", hasSource ? sourceStatus : "not_provided"},
        {"available", hasSource}}},
      {"file_authenticity",
       {{"status", hasFile ? fileSignatureStatus
                           : "not_provided"},
        {"available", signatureChecked}}},
      {"file_characteristics",
       {{"status", hasFile ? "checked" : "not_provided"},
        {"available", hasFile}}},
      {"redirect_destination",
       {{"status", !hasSource
                       ? "not_provided"
                       : hasRedirectSignal
                             ? "parameter_detected_redirect_not_followed"
                             : "no_nested_redirect_parameter_detected"},
        {"available", hasSource && hasRedirectSignal}}},
      {"threat_intelligence",
       {{"status", "not_configured"}, {"available", false}}},
      {"publisher_consistency",
       {{"status", publisherCompared ? "compared"
                                     : publisherComparisonAvailable
                                           ? "signer_available"
                                     : scores["publisher_consistency"] > 0
                                           ? "risk_signal_detected"
                                           : "not_available"},
        {"available", publisherEvidenceAvailable}}}};

  if (hasSource) {
    weights["source_domain"] = software_risk::config::SourceDomainWeight;
    if (hasRedirectSignal)
      weights["redirect_destination"] =
          software_risk::config::RedirectWeight;
  }
  if (hasFile) {
    if (signatureChecked)
      weights["file_authenticity"] =
          software_risk::config::FileAuthenticityWeight;
    weights["file_characteristics"] =
        software_risk::config::FileCharacteristicsWeight;
  }
  if (publisherEvidenceAvailable)
    weights["publisher_consistency"] =
        software_risk::config::PublisherConsistencyWeight;

  for (const auto &category : families)
    if (scores.count(category.first))
      scores[category.first] = familyScore(category.second);
  const int weightedTotal = weightedScore(scores, weights);
  int applicableCount = 0;
  for (const auto &entry : dimensionStatus)
    if (entry.value("available", false))
      ++applicableCount;
  const int completeness = static_cast<int>(
      std::lround(applicableCount * 100.0 / dimensionStatus.size()));
  int confidenceTotal = 0;
  int confidenceCount = 0;
  for (const auto &signal : signals)
    if (signal.is_object() && signal.value("score", 0) > 0) {
      confidenceTotal += bounded(signal.value("confidence", 0));
      ++confidenceCount;
    }
  const int evidenceConfidence =
      confidenceCount ? confidenceTotal / confidenceCount : 0;
  const int analysisConfidence = bounded(static_cast<int>(std::lround(
      completeness * 0.65 + evidenceConfidence * 0.35)));
  int independentRiskFamilies = 0;
  int strongRiskFamilies = 0;
  for (const auto &categoryFamilies : families)
    for (const auto &family : categoryFamilies.second) {
      if (family.second >= 40)
        ++independentRiskFamilies;
      if (family.second >= 60)
        ++strongRiskFamilies;
    }
  const bool localMalwareDetection =
      std::any_of(signals.begin(), signals.end(), [](const J &signal) {
        return signal.is_object() &&
               signal.value("id", S()) == "local_malware_detection";
      });
  const bool confirmedPublisherMismatch =
      std::any_of(signals.begin(), signals.end(), [](const J &signal) {
        return signal.is_object() &&
               signal.value("id", S()) == "declared_publisher_mismatch" &&
               signal.value("verification_status", S()) ==
                   "configured_reference_comparison";
      });
  const bool publisherIdentityUncertain =
      std::any_of(signals.begin(), signals.end(), [](const J &signal) {
        return signal.is_object() &&
               signal.value("id", S()) == "publisher_identity_uncertain";
      });
  const bool unverifiedDownloadSource =
      sourceStatus == "UNVERIFIED" && hasSource;
  const bool suspiciousDownloadSource = sourceStatus == "SUSPICIOUS";
  const bool corroborationCapped =
      !unverifiedDownloadSource && !suspiciousDownloadSource &&
      weightedTotal >= software_risk::config::HighRiskThreshold &&
      strongRiskFamilies < 2 && !localMalwareDetection &&
      !confirmedPublisherMismatch;
  const int overall =
      corroborationCapped ? software_risk::config::HighRiskThreshold - 1
                          : suspiciousDownloadSource || unverifiedDownloadSource
                                ? std::max(61, weightedTotal)
                                : publisherIdentityUncertain
                                      ? std::max(36, weightedTotal)
                                      : weightedTotal;
  const S category = riskCategory(overall);
  J weightJson = {
      {"source_domain", software_risk::config::SourceDomainWeight},
      {"file_authenticity", software_risk::config::FileAuthenticityWeight},
      {"file_characteristics",
       software_risk::config::FileCharacteristicsWeight},
      {"redirect_destination", software_risk::config::RedirectWeight},
      {"threat_intelligence",
       software_risk::config::ThreatIntelligenceWeight},
      {"publisher_consistency",
       software_risk::config::PublisherConsistencyWeight}};
  J categoryScores = J::object();
  for (const auto &entry : scores)
    categoryScores[entry.first] = bounded(entry.second);
  const int applicableWeight = [&]() {
    int total = 0;
    for (const auto &entry : weights)
      total += entry.second;
    return total;
  }();
  J assessment = {
      {"signals", signals},
      {"category_scores", categoryScores},
      {"weights", weightJson},
      {"applicable_weights", weights},
      {"applicable_weight_total", applicableWeight},
      {"weighted_score", overall},
      {"uncapped_weighted_score", weightedTotal},
      {"corroboration",
       {{"independent_risk_families", independentRiskFamilies},
        {"strong_risk_families", strongRiskFamilies},
        {"high_risk_cap_applied", corroborationCapped},
        {"explanation",
         "At least two independent strong risk-signal families are required "
          "for a Highly Risky score, except for a local antivirus detection or "
          "a confirmed mismatch with a configured product-publisher reference."}}},
      {"summary",
       "The risk score is a normalized weighted combination of available "
        "source, file, redirect, and publisher evidence. A confirmed publisher "
        "mismatch is a high-severity identity contradiction; otherwise, a "
        "Highly Risky score requires multiple independent strong indicators or "
        "a local antivirus detection. Missing checks are reported separately "
        "and do not count as evidence of malicious activity or safety."},
      {"completeness",
       {{"score", completeness},
        {"label", completenessLabel(completeness)},
        {"available_dimensions", applicableCount},
        {"total_dimensions", dimensionStatus.size()},
        {"dimensions", dimensionStatus},
        {"missing_evidence", limitations}}},
      {"confidence",
       {{"score", analysisConfidence},
        {"label", completenessLabel(analysisConfidence)},
        {"explanation",
         "Confidence describes how much evidence was checked, not whether "
         "the file or publisher is legitimate."}}},
      {"positive_evidence", positiveEvidence},
      {"limitations", limitations},
      {"product_context",
       {{"product", product},
        {"known_publishers", knownPublishers},
        {"declared_publisher", declaredPublisher}}},
      {"threat_intelligence",
       {{"status", "not_configured"},
        {"provider", nullptr},
        {"file_uploaded", false},
        {"explanation",
         "No file or hash was sent to an external reputation service. "
         "Threat-intelligence lookup is not configured."}}},
      {"redirects",
       {{"status", hasSource ? "not_followed" : "not_provided"},
        {"explanation",
         "Pasted URLs are analyzed locally. CyberShield does not open the URL "
         "or follow network redirects."}}}};

  report["score"] = overall;
  report["category"] = category;
  report["trust_score"] = nullptr;
  report["source_status"] = sourceStatus;
  const S sourceExplanation =
      sourceStatus == "VERIFIED_OFFICIAL"
          ? "The hostname and applicable path match a configured official "
            "source reference. The site was not opened, and the downloaded "
            "file was not verified."
      : sourceStatus == "SUSPICIOUS"
          ? "Source or product consistency indicators are suspicious. Do not "
            "use this address for a download."
      : sourceStatus == "VERIFICATION_ERROR"
          ? "Source verification could not complete. Do not treat this "
            "address as trusted."
          : hasSource
                ? "CyberShield could not establish this address as an "
                  "official source. It is unverified, not confirmed "
                  "malicious."
                : "No download address was supplied, so source authenticity "
                  "could not be established.";
  report["source_verification"] = {
      {"status", sourceStatus}, {"explanation", sourceExplanation}};
  if (sourceStatus != "VERIFIED_OFFICIAL")
    report.erase("source_reference");
  report["software_assessment"] = std::move(assessment);
  if (hasFile) {
    report["file_details"] = {
        {"name", file.value("file_name", S())},
        {"size_bytes", file.value("size_bytes", 0)},
        {"type", file.value("file_type", S())},
        {"sha256", file.value("sha256", S())},
        {"authenticode", file.value("authenticode", J::object())}};
  }
  return report;
}
