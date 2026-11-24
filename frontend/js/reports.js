import { esc, icon, date } from "./common.js";
export function displayedCategory(report) {
  if (report.type === "Software" && report.category === "Lower risk") {
    return /product and download location match|address matches a location in the publisher reference catalogue/i.test(
      report.basis || "",
    )
      ? "Listed source"
      : "Insufficient information";
  }
  if (report.type !== "Website") return report.category;
  if (report.category === "High risk") return "Highly Risky";
  if (
    report.category === "Unable to Verify" &&
    Number.isInteger(report.observed_score) &&
    report.observed_score >= 61
  )
    return "Highly Risky";
  if (
    report.category === "Unable to Verify" &&
    Number.isInteger(report.observed_score) &&
    report.observed_score >= 36
  )
    return "Be Cautious";
  if (report.category === "Unable to Verify") return "";
  return report.category;
}

export function reportHtml(r) {
  const category = displayedCategory(r);
  let tone =
    category === "Highly Risky"
      ? "high"
      : (
    {
      "Highly Risky": "high",
      "Be Cautious": "moderate",
      Safe: "low",
      "High risk": "high",
      "Moderate Risk": "moderate",
      Suspicious: "moderate",
      "Low Risk": "low",
      "Low risk": "low",
      "Low risk signals detected": "low",
      Caution: "moderate",
      "No Known Issues Detected": "low",
      "Insufficient information": "unknown",
      "Recognized source": "unknown",
      "Known legitimate source": "unknown",
      "Unverified source": "unknown",
      "Listed source": "unknown",
      "Unable to Verify": "unknown",
      Dangerous: "high",
      "No known threats detected": "low",
      "Unable to verify": "unknown",
      "Lower risk": "low",
      Unverified: "unknown",
    }[category] || "unknown");
  const isSms = r.type === "SMS";
  const title = r.type === "Email"
    ? "Email analysis"
    : isSms
      ? "SMS scam analysis"
      : r.target;
  const isWebsite = r.type === "Website";
  const isSoftware = r.type === "Software";
  const isEmail = r.type === "Email";
  if (isSoftware) {
    const score = typeof r.score === "number" ? r.score : null;
    if (score !== null)
      tone = score >= 61 ? "high" : score >= 36 ? "moderate" : "low";
  }
  const smsAssessment = isSms ? r.sms_assessment || {} : {};
  const emailAssessment = isEmail ? r.email_assessment || {} : {};
  const softwareAssessment = isSoftware ? r.software_assessment || {} : {};
  const softwareCorroboration = softwareAssessment.corroboration || {};
  const hasTrustScore = typeof r.trust_score === "number";
  const trustScore = hasTrustScore ? r.trust_score : null;
  const hasScore = typeof r.score === "number";
  if (isSms && hasScore) {
    tone = r.score >= 61 ? "high" : r.score >= 36 ? "moderate" : "low";
  }
  if (isWebsite && hasScore) {
    tone = r.score >= 61 ? "high" : r.score >= 36 ? "moderate" : "low";
  }
  const hasObservedScore =
    isWebsite && !hasScore && Number.isInteger(r.observed_score);
  const confidence = r.confidence;
  const checks = Array.isArray(r.checks) ? r.checks : [];
  const tldStatus = r.tld_policy
    ? {
        approved: "Passed",
        unapproved: "Failed",
        not_applicable: "Not applicable",
      }[r.tld_policy.status] || "Unavailable"
    : "";
  const tldPolicyHtml =
    isWebsite && r.tld_policy
      ? '<section class="report-basis"><h3>Approved TLD check</h3><p><strong>' +
        tldStatus +
        "</strong>" +
        (r.tld_policy.tld ? " · " + esc(r.tld_policy.tld) : "") +
        "<br>" +
        esc(r.tld_policy.explanation) +
        "</p></section>"
      : "";
  const findingRows =
    isSoftware && Array.isArray(softwareAssessment.signals)
      ? softwareAssessment.signals
      : Array.isArray(r.findings)
        ? r.findings
        : [];
  const findings = findingRows
    .map((finding) => {
      if (isSoftware) {
        const status =
          finding.verification_status === "verified_from_file_bytes" ||
          finding.verification_status === "local_engine_result" ||
          finding.verification_status === "local_signature_verification"
            ? "Locally verified evidence"
            : finding.verification_status === "configured_reference_comparison"
              ? "Compared with a configured reference; not authentication"
              : finding.verification_status === "not_in_registry"
                ? "Not listed in the local registry; not confirmed malicious"
                : "Heuristic; not independently verified";
        const categoryLabels = {
          source_domain: "Source and domain",
          file_authenticity: "File authenticity",
          file_characteristics: "File characteristics",
          redirect_destination: "Redirect destination",
          threat_intelligence: "Threat intelligence",
          publisher_consistency: "Publisher consistency",
        };
        return (
          '<li class="email-signal"><strong>' +
          esc(finding.name || "Software signal") +
          '<small class="signal-severity">' +
          esc(finding.severity || "Observation") +
          "</small></strong><span>" +
          (finding.category
            ? "<small>Category: " +
              esc(categoryLabels[finding.category] || finding.category) +
              "</small><br>"
            : "") +
          esc(finding.text || "") +
          (finding.evidence
            ? '<br><small>Evidence: <bdi>' +
              esc(finding.evidence) +
              "</bdi></small>"
            : "") +
          (Number(finding.score) > 0
            ? "<br><small>Signal strength: " +
              Math.max(0, Math.min(100, Number(finding.score) || 0)) +
              "/100</small>"
            : "") +
          '<br><small class="evidence-status">' +
          esc(status) +
          (finding.detection_method
            ? " · " + esc(finding.detection_method)
            : "") +
          "</small></span></li>"
        );
      }
      if (isSms) {
        const verification =
          finding.verification_status ===
          "configured_reference_comparison"
            ? "Compared with a configured reference; not authentication"
            : finding.verification_status === "verified_from_text"
              ? "Observed in the pasted text"
              : "Heuristic; not independently verified";
        return (
          '<li class="email-signal"><strong>' +
          esc(finding.name || "Signal") +
          '<small class="signal-severity">' +
          esc(finding.severity || "observation") +
          "</small></strong><span>" +
          (finding.category
            ? "<small>Category: " +
              esc(finding.category.replaceAll("_", " ")) +
              "</small><br>"
            : "") +
          esc(finding.text || "") +
          (finding.evidence
            ? '<br><small>Evidence: <bdi>' +
              esc(finding.evidence) +
              "</bdi></small>"
            : finding.evidence_status === "omitted_from_history"
              ? "<br><small>Evidence excerpt omitted from saved history for privacy.</small>"
              : "") +
          '<br><small class="evidence-status">' +
          esc(verification) +
          (finding.detection_method
            ? " · " + esc(finding.detection_method)
            : "") +
          "</small></span></li>"
        );
      }
      if (isEmail) {
        const status =
          finding.evidence_status === "provided_unverified"
            ? "User-supplied · not independently verified"
            : finding.evidence_status === "unknown"
              ? "Unknown"
              : "Heuristic";
        return (
          '<li class="email-signal"><strong>' +
          esc(finding.name || finding.severity || "Signal") +
          '<small class="signal-severity">' +
          esc(finding.severity || "observation") +
          "</small></strong><span>" +
          (finding.category
            ? "<small>Category: " + esc(finding.category) + "</small><br>"
            : "") +
          esc(finding.text || "") +
          (finding.evidence
            ? '<br><small>Evidence: <bdi>' +
              esc(finding.evidence) +
              "</bdi></small>"
            : "") +
          '<br><small class="evidence-status">' +
          esc(status) +
          "</small></span></li>"
        );
      }
      return (
        "<li><strong>" +
        (Number(finding.points) > 0
          ? Number(finding.points) + " signal points"
          : esc(finding.severity || "Observation")) +
        (Number(finding.points) > 0
          ? " · " +
            esc(finding.severity || "signal") +
            " · " +
            Number(finding.reliability || 0) +
            "% reliability"
          : "") +
        "</strong><span>" +
        (finding.category
          ? "<small>Category: " + esc(finding.category) + "</small><br>"
          : "") +
        esc(finding.text) +
        (finding.evidence
          ? "<br><small>Evidence: " + esc(finding.evidence) + "</small>"
          : "") +
        "</span></li>"
      );
    })
    .join("");
  const emailCategoryLabels = {
    urgency_manipulation: "Urgency and manipulation",
    link_destination: "Link and destination",
    sender_authenticity: "Sender authenticity",
    financial_sensitive_action: "Financial and sensitive actions",
    content_suspiciousness: "Content suspiciousness",
  };
  const emailScoresHtml =
    isEmail && emailAssessment.category_scores
      ? '<section class="email-assessment"><h3>Risk dimensions</h3><div class="email-score-grid">' +
        Object.entries(emailCategoryLabels)
          .map(([key, label]) => {
            const value = Math.max(
              0,
              Math.min(100, Number(emailAssessment.category_scores[key]) || 0),
            );
            const weight = Number(emailAssessment.weights?.[key]) || 0;
            return (
              '<div class="email-score-item"><div><strong>' +
              esc(label) +
              "</strong><b>" +
              value +
              "/100</b></div><div class=\"email-score-track\" role=\"meter\" aria-label=\"" +
              esc(label) +
              '" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
              value +
              '"><span style="width:' +
              value +
              '%"></span></div><small>Weight: ' +
              weight +
              "%</small></div>"
            );
          })
          .join("") +
        "</div><small>Category scores are combined using the configured "
        + "weights and limited interaction adjustments.</small></section>"
      : "";
  const emailConfidence = emailAssessment.confidence;
  const emailConfidenceHtml =
    isEmail && emailConfidence
      ? '<section class="email-confidence"><strong>Analysis completeness · ' +
        esc(emailConfidence.label || "Unknown") +
        " (" +
        Math.max(0, Math.min(100, Number(emailConfidence.score) || 0)) +
        "/100)</strong><p>This measures the evidence available to the checker, "
        + "not whether the sender or email is legitimate.</p>" +
        (emailConfidence.missing_evidence?.length
          ? "<ul>" +
            emailConfidence.missing_evidence
              .map((item) => "<li>" + esc(item) + "</li>")
              .join("") +
            "</ul>"
          : "") +
        "</section>"
      : "";
  const emailLinks = emailAssessment.links;
  const emailLinksHtml =
    isEmail && Array.isArray(emailLinks?.items) && emailLinks.items.length
      ? '<section class="email-links"><h3>Link destinations · not opened</h3><ul>' +
        emailLinks.items
          .map(
            (item) =>
              "<li><strong>" +
              esc(item.host || "Host not verified") +
              "</strong><small>" +
              esc(String(item.source || "link").replaceAll("_", " ")) +
              " · " +
              esc(String(item.status || "unknown").replaceAll("_", " ")) +
              "</small><code>" +
              esc(item.destination || "") +
              "</code>" +
              (item.visible_text
                ? "<small>Displayed as: " + esc(item.visible_text) + "</small>"
                : "") +
              "</li>",
          )
          .join("") +
        "</ul></section>"
      : "";
  const emailLimitationsHtml =
    isEmail && Array.isArray(emailAssessment.limitations)
      ? '<section class="email-limitations"><h3>Analysis limitations</h3><ul>' +
        emailAssessment.limitations
          .map((item) => "<li>" + esc(item) + "</li>")
          .join("") +
        "</ul></section>"
      : "";
  const emailPositiveHtml =
    isEmail && Array.isArray(emailAssessment.positive_evidence) &&
    emailAssessment.positive_evidence.length
      ? '<section class="email-positive"><h3>Supporting evidence · not proof</h3><ul>' +
        emailAssessment.positive_evidence
          .map(
            (item) =>
              "<li><strong>" +
              esc(item.name || "Observed") +
              "</strong><span>" +
              esc(item.evidence || "") +
              (item.note
                ? "<br><small>" + esc(item.note) + "</small>"
                : "") +
              "</span></li>",
          )
          .join("") +
        "</ul></section>"
      : "";
  const smsCategoryLabels = {
    link_destination: "Link and destination",
    sender_impersonation: "Sender and impersonation",
    requested_action_financial: "Sensitive or financial action",
    urgency_pressure: "Urgency and pressure",
    context_suspiciousness: "Contextual combinations",
  };
  const smsScoresHtml =
    isSms && smsAssessment.category_scores
      ? '<section class="email-assessment"><h3>Risk dimensions</h3><div class="email-score-grid">' +
        Object.entries(smsCategoryLabels)
          .map(([key, label]) => {
            const value = Math.max(
              0,
              Math.min(100, Number(smsAssessment.category_scores[key]) || 0),
            );
            const weight = Number(smsAssessment.weights?.[key]) || 0;
            return (
              '<div class="email-score-item"><div><strong>' +
              esc(label) +
              "</strong><b>" +
              value +
              "/100</b></div><div class=\"email-score-track\" role=\"meter\" aria-label=\"" +
              esc(label) +
              '" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
              value +
              '"><span style="width:' +
              value +
              '%"></span></div><small>Weight: ' +
              weight +
              "%</small></div>"
            );
          })
          .join("") +
        "</div><small>Weighted scores are adjusted only for independent "
        + "combinations of evidence.</small></section>"
      : "";
  const smsConfidence = smsAssessment.confidence;
  const smsConfidenceHtml =
    isSms && smsConfidence
      ? '<section class="email-confidence"><strong>Analysis confidence · ' +
        esc(smsConfidence.label || "Unknown") +
        " (" +
        Math.max(0, Math.min(100, Number(smsConfidence.score) || 0)) +
        "/100)</strong><p>" +
        esc(smsConfidence.explanation || "") +
        "</p></section>"
      : "";
  const smsCompleteness = smsAssessment.completeness;
  const smsCompletenessHtml =
    isSms && smsCompleteness
      ? '<section class="email-confidence"><strong>Analysis completeness · ' +
        esc(smsCompleteness.label || "Unknown") +
        " (" +
        Math.max(0, Math.min(100, Number(smsCompleteness.score) || 0)) +
        "/100)</strong><ul>" +
        Object.entries(smsCompleteness.components || {})
          .map(
            ([name, value]) =>
              "<li>" +
              esc(name.replaceAll("_", " ")) +
              ": " +
              Math.max(0, Math.min(100, Number(value) || 0)) +
              "%</li>",
          )
          .join("") +
        "</ul>" +
        (smsCompleteness.missing_evidence?.length
          ? "<p>Limitations:</p><ul>" +
            smsCompleteness.missing_evidence
              .map((item) => "<li>" + esc(item) + "</li>")
              .join("") +
            "</ul>"
          : "") +
        "</section>"
      : "";
  const smsSender = smsAssessment.sender;
  const smsSenderHtml =
    isSms && smsSender
      ? '<section class="email-confidence"><h3>Sender assessment</h3><p><strong>' +
        esc(
          smsSender.status === "registry_claim_mismatch"
            ? "Configured sender mismatch"
            : smsSender.status === "configured_registry_match"
            ? "Configured registry match"
            : smsSender.status === "unverified"
              ? "Unverified sender"
              : "Sender not provided",
        ) +
        "</strong>" +
        (smsSender.claimed_organization
          ? "<br>Message mentions: " +
            esc(smsSender.claimed_organization)
          : "") +
        (smsSender.registry_organization
          ? "<br>Registry entry: " +
            esc(smsSender.registry_organization)
          : "") +
        "<br>" +
        esc(smsSender.verification || "") +
        "</p></section>"
      : "";
  const smsLinks = smsAssessment.links;
  const smsLinksHtml =
    isSms && Array.isArray(smsLinks?.items) && smsLinks.items.length
      ? '<section class="email-links"><h3>Extracted link domains · not opened</h3><ul>' +
        smsLinks.items
          .map(
            (item) =>
              "<li><strong>" +
              esc(item.host || "Domain could not be parsed") +
              "</strong><small>" +
              esc(String(item.scheme || "unknown scheme").toUpperCase()) +
              " · " +
              esc(String(item.status || "unknown").replaceAll("_", " ")) +
              " · " +
              esc(
                String(item.verification_status || "unknown").replaceAll(
                  "_",
                  " ",
                ),
              ) +
              "</small>" +
              (Array.isArray(item.redirect_hosts) && item.redirect_hosts.length
                ? "<small>Redirect parameter hosts: " +
                  item.redirect_hosts.map((host) => esc(host)).join(", ") +
                  " (not followed)</small>"
                : "") +
              "</li>",
          )
          .join("") +
        "</ul><small>" +
        esc(smsLinks.note || "Links are analyzed locally and never opened.") +
        "</small></section>"
      : isSms && smsLinks
        ? '<section class="email-links"><h3>Link analysis</h3><p>No link destination was found in the pasted text. This does not check links omitted from the message.</p></section>'
        : "";
  const smsLimitationsHtml =
    isSms && Array.isArray(smsAssessment.limitations)
      ? '<section class="email-limitations"><h3>Analysis limitations</h3><ul>' +
        smsAssessment.limitations
          .map((item) => "<li>" + esc(item) + "</li>")
          .join("") +
        "</ul></section>"
      : "";
  const smsPositiveHtml =
    isSms &&
    Array.isArray(smsAssessment.positive_evidence) &&
    smsAssessment.positive_evidence.length
      ? '<section class="email-positive"><h3>Supporting evidence · not proof</h3><ul>' +
        smsAssessment.positive_evidence
          .map((item) => "<li>" + esc(item) + "</li>")
          .join("") +
        "</ul></section>"
      : "";
  const softwareCategoryLabels = {
    source_domain: "Source and domain",
    file_authenticity: "File authenticity",
    file_characteristics: "File characteristics",
    redirect_destination: "Redirect destination",
    threat_intelligence: "Threat intelligence",
    publisher_consistency: "Publisher and brand consistency",
  };
  const softwareScoresHtml =
    isSoftware && softwareAssessment.category_scores
      ? '<section class="email-assessment"><h3>Risk dimensions</h3><div class="email-score-grid">' +
        Object.entries(softwareCategoryLabels)
          .map(([key, label]) => {
            const value = Math.max(
              0,
              Math.min(
                100,
                Number(softwareAssessment.category_scores[key]) || 0,
              ),
            );
            const weight = Number(softwareAssessment.weights?.[key]) || 0;
            const status =
              softwareAssessment.completeness?.dimensions?.[key]?.status ||
              "unknown";
            return (
              '<div class="email-score-item"><div><strong>' +
              esc(label) +
              "</strong><b>" +
              value +
              "/100</b></div><div class=\"email-score-track\" role=\"meter\" aria-label=\"" +
              esc(label) +
              '" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
              value +
              '"><span style="width:' +
              value +
              '%"></span></div><small>Weight: ' +
              weight +
              "% · " +
              esc(String(status).replaceAll("_", " ")) +
              "</small></div>"
            );
          })
          .join("") +
        "</div><small>Scores use normalized weights for the checks that "
        + "actually ran. Missing checks do not imply safety.</small></section>"
      : "";
  const softwareCompleteness = softwareAssessment.completeness;
  const softwareConfidence = softwareAssessment.confidence;
  const softwareCompletenessHtml =
    isSoftware && softwareCompleteness
      ? '<section class="email-confidence"><strong>Analysis completeness · ' +
        esc(softwareCompleteness.label || "Unknown") +
        " (" +
        Math.max(0, Math.min(100, Number(softwareCompleteness.score) || 0)) +
        "/100)</strong><p>Coverage describes which checks ran, not whether "
        + "the software is safe.</p>" +
        (softwareConfidence
          ? "<p><strong>Analysis confidence · " +
            Math.max(0, Math.min(100, Number(softwareConfidence.score) || 0)) +
            "/100</strong> " +
            esc(softwareConfidence.explanation || "") +
            "</p>"
          : "") +
        (softwareCompleteness.missing_evidence?.length
          ? "<ul>" +
            softwareCompleteness.missing_evidence
              .map((item) => "<li>" + esc(item) + "</li>")
              .join("") +
            "</ul>"
          : "") +
        (softwareAssessment.threat_intelligence
          ? "<p>" +
            esc(softwareAssessment.threat_intelligence.explanation || "") +
            "</p>"
          : "") +
        "</section>"
      : "";
  const softwareFileDetails = r.file_details;
  const softwareFileHtml =
    isSoftware && softwareFileDetails
      ? '<section class="email-links"><h3>Selected file analysis</h3><p><strong>' +
        esc(softwareFileDetails.name || "Selected file") +
        "</strong><br>" +
        esc(softwareFileDetails.type || "File type unavailable") +
        " · " +
        Number(softwareFileDetails.size_bytes || 0).toLocaleString() +
        " bytes<br>SHA-256: <code>" +
        esc(softwareFileDetails.sha256 || "Unavailable") +
        "</code><br>Authenticode: " +
        esc(
          softwareFileDetails.authenticode?.status || "not checked",
        ) +
        (softwareFileDetails.authenticode?.signer
          ? "<br>Signer: " +
            esc(softwareFileDetails.authenticode.signer)
          : "") +
        (softwareFileDetails.authenticode?.message
          ? "<br>" +
            esc(softwareFileDetails.authenticode.message)
          : "") +
        "</p></section>"
      : "";
  const softwareSourceHtml =
    isSoftware
      ? '<section class="email-links"><h3>Download source · not opened</h3>' +
        (r.source_url
          ? "<p>Submitted address: <code><bdi>" +
            esc(r.source_url) +
            "</bdi></code></p>"
          : "") +
        (r.hostname ? "<p>Parsed hostname: <strong>" + esc(r.hostname) + "</strong></p>" : "") +
        "<p class=\"report-basis\"><strong>" +
        esc(
          {
            VERIFIED_OFFICIAL: "Verified official source reference",
            UNVERIFIED: "Unverified Source",
            SUSPICIOUS: "Suspicious Source",
            VERIFICATION_ERROR: "Source Verification Error",
            recognized: "Verified official source reference",
            known_legitimate: "Unverified Source",
            unverified: "Unverified Source",
          }[r.source_verification?.status || r.source_status] ||
            "Unverified Source",
        ) +
            "<br>" +
            esc(
              r.source_verification?.explanation ||
                "CyberShield could not establish this address as an official source.",
            ) +
            "</p>" +
        (r.source_reference &&
        ["VERIFIED_OFFICIAL", "recognized"].includes(
          r.source_verification?.status || r.source_status,
        )
          ? "<p>Configured reference: " +
            esc(r.source_reference.source || "") +
            ' · <a rel="noopener noreferrer" target="_blank" href="' +
            esc(r.source_reference.url || "") +
            '">' +
            esc(r.source_reference.url || "") +
            "</a></p>"
          : "") +
        "</section>"
      : "";
  const scoring = r.scoring;
  const independentCategories = Number(scoring?.independent_categories || 0);
  const scoringHtml =
    isWebsite && scoring && !hasObservedScore
      ? '<section class="report-basis"><h3>Score calculation</h3><p>' +
        (typeof scoring.total === "number"
          ? "min(100, category subtotal "
          : "Collected-evidence score: ") +
        Number(scoring.category_subtotal) +
        (typeof scoring.total === "number"
          ? " + independent-evidence corroboration " +
            Number(scoring.corroboration_bonus) +
            ") = " +
            Number(scoring.total)
          : "/100 (incomplete)") +
        ". " +
        independentCategories +
        (independentCategories === 1
          ? " independent category contributed at least 10 points.</p>"
          : " independent categories contributed at least 10 points.</p>") +
        (Object.keys(scoring.category_points || {}).length
          ? "<ul>" +
            Object.entries(scoring.category_points)
              .map(
                ([name, points]) =>
                  "<li>" + esc(name) + ": " + Number(points) + "</li>",
              )
              .join("") +
            "</ul>"
          : "<p>No category contributed risk points.</p>") +
        "<small>Raw finding points are weighted by reliability, grouped by "
        + "correlated evidence families, and limited by category caps. "
        + "Missing checks do not add risk.</small></section>"
      : "";
  const coverage = Array.isArray(r.indicator_coverage)
    ? r.indicator_coverage
    : [];
  const coverageHtml =
    isWebsite && coverage.length && !hasObservedScore
      ? "<details><summary>A–Z indicator framework coverage</summary><ul class=\"evidence\">" +
        coverage
          .map(
            (item) =>
              "<li><strong>" +
              esc(item.letter + " · " + item.category + " · " + item.status) +
              "</strong><span>" +
              esc(item.details) +
              "</span></li>",
          )
          .join("") +
        "</ul><small>The framework lists meaningful checks only; unavailable "
        + "sources are marked not checked and are not guessed.</small></details>"
      : "";
  const confidenceHtml =
    isWebsite && confidence && !hasObservedScore
      ? '<section class="report-basis"><h3>Scan confidence</h3><p>' +
        Number(confidence.completed) +
        " of " +
        Number(confidence.applicable) +
        " applicable checks completed (" +
        Number(confidence.percentage) +
        "% confidence coverage). " +
        Math.max(0, Number(confidence.planned) - Number(confidence.applicable)) +
        " check(s) were not applicable. This is inspection coverage, not a "
        + "probability that the site is safe.</p></section>"
      : "";
  const checksHtml =
    isWebsite && checks.length && !hasObservedScore
      ? "<h3>Inspection checks</h3><ul class=\"evidence\">" +
        checks
          .map(
            (item) =>
              "<li><strong>" +
              esc(item.name) +
              " · " +
              esc(String(item.status).replaceAll("_", " ")) +
              "</strong><span>" +
              esc(item.summary) +
              (item.evidence.length
                ? "<br><small>" +
                  item.evidence.map((line) => esc(line)).join("<br>") +
                  "</small>"
                : "") +
              "</span></li>",
          )
          .join("") +
        "</ul>"
      : "";
  return (
    '<section class="card result risk-' +
    tone +
    '"><div class="resulthead">' +
    (category
      ? '<span class="tag">' + esc(category) + "</span>"
      : "") +
    "<small>" +
    esc(date(r.date)) +
    "</small></div><h2>" +
    esc(title) +
    "</h2>" +
    ((isEmail || isSms) && hasScore
      ? '<div class="risknumber"><strong>' +
        r.score +
        '</strong><small class="score-caption">Risk score · /100</small></div><div class="meter"><span style="width:' +
        r.score +
        '%"></span></div><small class="score-explanation">Higher risk scores mean more warning signs.</small>'
      : isWebsite && hasScore
      ? '<div class="risknumber"><strong>' +
        r.score +
        '</strong><small class="score-caption">Risk score · /100</small></div><div class="meter"><span style="width:' +
        r.score +
        '%"></span></div>'
      : isSoftware && hasScore
        ? '<div class="risknumber"><strong>' +
          r.score +
          '</strong><small class="score-caption">Risk score · /100</small></div><div class="meter"><span style="width:' +
          r.score +
          '%"></span></div>'
      : hasObservedScore
        ? '<div class="risknumber"><strong>' +
          Number(r.observed_score) +
          '</strong><small class="score-caption">Risk score · /100</small></div><div class="meter"><span style="width:' +
          Number(r.observed_score) +
          '%"></span></div>'
      : isEmail
        ? '<p class="report-basis">Risk score unavailable for this saved report. Run a new analysis to generate one.</p>'
      : trustScore !== null
      ? '<div class="risknumber"><strong>' +
        trustScore +
        '</strong><small class="score-caption">Trust score · /100</small></div><div class="meter"><span style="width:' +
        trustScore +
        '%"></span></div>' +
        (hasScore ? '<small><strong>Risk score:</strong> ' + r.score + '/100</small>' : '')
      : isWebsite
        ? '<p class="report-basis">No score could be calculated from the available evidence.</p>'
        : '<p class="report-basis">Trust score unavailable for this saved report. Run a new analysis to generate one.</p>') +
    tldPolicyHtml +
    (isEmail && emailAssessment.summary
      ? '<section class="email-summary"><h3>Why this score</h3><p>' +
        esc(emailAssessment.summary) +
        '</p><small>Weighted score ' +
        Math.max(0, Math.min(100, Number(emailAssessment.weighted_score) || 0)) +
        " + combination adjustment " +
        Math.max(
          0,
          Math.min(18, Number(emailAssessment.interaction_adjustment) || 0),
        ) +
        " = " +
        Math.max(0, Math.min(100, Number(r.score) || 0)) +
        "/100.</small></section>"
      : "") +
    (isSms && smsAssessment.summary
      ? '<section class="email-summary"><h3>Why this score</h3><p>' +
        esc(smsAssessment.summary) +
        '</p><small>Weighted score ' +
        Math.max(0, Math.min(100, Number(smsAssessment.weighted_score) || 0)) +
        " + independent-evidence adjustment " +
        Math.max(
          0,
          Math.min(
            36,
            Number(smsAssessment.interaction_adjustment) || 0,
          ),
        ) +
        " = " +
        Math.max(0, Math.min(100, Number(r.score) || 0)) +
        "/100.</small>" +
        (Array.isArray(smsAssessment.interaction_reasons) &&
        smsAssessment.interaction_reasons.length
          ? "<ul>" +
            smsAssessment.interaction_reasons
              .map((item) => "<li>" + esc(item) + "</li>")
              .join("") +
            "</ul>"
          : "") +
        "</section>"
      : "") +
    emailScoresHtml +
    emailConfidenceHtml +
    emailLinksHtml +
    emailLimitationsHtml +
    emailPositiveHtml +
    smsScoresHtml +
    smsConfidenceHtml +
    smsCompletenessHtml +
    smsSenderHtml +
    smsLinksHtml +
    smsLimitationsHtml +
    smsPositiveHtml +
    (isSoftware && softwareAssessment.summary
      ? '<section class="email-summary"><h3>Why this score</h3><p>' +
        esc(softwareAssessment.summary) +
        "</p><small>Uncapped normalized weighted score: " +
        Math.max(
          0,
          Math.min(
            100,
            Number(
              softwareAssessment.uncapped_weighted_score ??
                softwareAssessment.weighted_score,
            ) || 0,
          ),
        ) +
        "/100. Final risk score: " +
        Math.max(0, Math.min(100, Number(r.score) || 0)) +
        "/100." +
        (softwareCorroboration.high_risk_cap_applied
          ? " High-risk cap applied: only " +
            Number(softwareCorroboration.strong_risk_families || 0) +
            " strong independent signal family/families were available."
          : "") +
        "</small></section>"
      : "") +
    softwareScoresHtml +
    softwareCompletenessHtml +
    softwareSourceHtml +
    softwareFileHtml +
    (isSoftware && Array.isArray(softwareAssessment.positive_evidence) &&
    softwareAssessment.positive_evidence.length
      ? '<section class="email-positive"><h3>Supporting evidence · not proof</h3><ul>' +
        softwareAssessment.positive_evidence
          .map((item) => "<li>" + esc(item) + "</li>")
          .join("") +
        "</ul></section>"
      : "") +
    (isSoftware && Array.isArray(softwareAssessment.limitations)
      ? '<section class="email-limitations"><h3>Analysis limitations</h3><ul>' +
        softwareAssessment.limitations
          .map((item) => "<li>" + esc(item) + "</li>")
          .join("") +
        "</ul></section>"
      : "") +
    (!hasObservedScore && r.basis
      ? '<p class="report-basis">' + esc(r.basis) + "</p>"
      : "") +
    (!hasObservedScore && r.dns ? "<p>" + esc(r.dns) + "</p>" : "") +
    confidenceHtml +
    scoringHtml +
    (isEmail || isSms
      ? "<h3>Important signals</h3>"
      : !isWebsite && ["Software"].includes(r.type)
      ? "<h3>Score breakdown</h3>"
      : "<h3>Detected indicators</h3>") +
    (findings
      ? '<ul class="evidence">' + findings + "</ul>"
      : "<p>" +
        (hasScore
          ? isWebsite
            ? "No risk indicators contributed points."
            : isSms
              ? "No local scam indicators were found in the pasted text."
              : "No local rules raised a warning."
          : r.basis
            ? "See the evidence below for the checks completed."
            : "See the scan summary below.") +
        "</p>") +
    checksHtml +
    (hasObservedScore
      ? ""
      : '<div class="recommend"><h3>Recommended action</h3><p>' +
        esc(r.advice) +
        "</p></div>") +
    '<details class="advanced"' +
    (!hasObservedScore &&
    ["Website", "Software", "Email", "SMS", "File"].includes(r.type)
      ? " open"
      : "") +
    "><summary>Evidence and limitations</summary>" +
    (!hasObservedScore && r.reputation
      ? "<p>" + esc(r.reputation) + "</p>"
      : "") +
    coverageHtml +
    (hasObservedScore
      ? ""
      : r.notes.map((n) => "<p>" + esc(n) + "</p>").join("")) +
    "<small>Source · " +
    esc(r.source) +
    "</small></details><button data-export-pdf>" +
    icon("download") +
    " Download PDF</button></section>"
  );
}
let library;
export async function pdf(r) {
  const hasObservedScore =
    r.type === "Website" &&
    typeof r.score !== "number" &&
    Number.isInteger(r.observed_score);
  if (!library)
    library = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "/assets/vendor/jspdf.js";
      s.onload = resolve;
      s.onerror = () => {
        library = null;
        reject(Error("PDF library unavailable."));
      };
      document.head.append(s);
    });
  await library;
  const doc = new window.jspdf.jsPDF();
  let y = 24;
  function line(s, size = 11) {
    doc.setFontSize(size);
    const lines = doc.splitTextToSize(
      String(s).replace(/[’]/g, "'").replace(/[–—]/g, "-"),
      171,
    );
    for (const text of lines) {
      if (y > 273) {
        doc.addPage();
        y = 22;
      }
      doc.text(text, 20, y);
      y += size * 0.48;
    }
    y += 4;
  }
  doc.setTextColor(18, 52, 75);
  line("CyberShield", 24);
  line(r.type + " scan report", 17);
  line(date(r.date));
  line(
    "Target: " +
      (r.type === "Email"
        ? "Email analysis"
        : r.type === "SMS"
          ? "SMS scam analysis"
          : r.target),
  );
  line(
    hasObservedScore
      ? (displayedCategory(r)
          ? "Assessment: " + displayedCategory(r) + " | "
          : "") +
          "Score: " + r.observed_score + "/100"
      : "Assessment: " +
      displayedCategory(r) +
      (r.type === "Website" && typeof r.score === "number"
        ? " | Risk score: " + r.score + "/100"
        : r.type === "Website"
        ? " | Risk score unavailable"
          : r.type === "Software" && typeof r.score === "number"
          ? " | Risk score: " + r.score + "/100"
        : r.type === "Email" || r.type === "SMS"
        ? typeof r.score === "number"
          ? " | Risk score: " + r.score + "/100"
          : " | Risk score unavailable"
        : typeof r.trust_score === "number"
        ? " | Trust score: " + r.trust_score + "/100"
        : " | Trust score unavailable for this saved report"),
  );
  if (r.type === "Email" && r.email_assessment) {
        const assessment = r.email_assessment;
        const labels = {
          urgency_manipulation: "Urgency and manipulation",
          link_destination: "Link and destination",
          sender_authenticity: "Sender authenticity",
          financial_sensitive_action: "Financial and sensitive actions",
          content_suspiciousness: "Content suspiciousness",
        };
        line(assessment.summary || "Weighted email risk assessment", 12);
        line("Category risk scores", 14);
        for (const [key, label] of Object.entries(labels))
          line(
            label +
              ": " +
              Number(assessment.category_scores?.[key] || 0) +
              "/100 (weight " +
              Number(assessment.weights?.[key] || 0) +
              "%)",
          );
        if (assessment.confidence)
          line(
            "Analysis completeness: " +
              assessment.confidence.label +
              " (" +
              Number(assessment.confidence.score) +
              "/100). This is evidence coverage, not a legitimacy rating.",
          );
    for (const reason of assessment.interaction_reasons || [])
          line("Combination adjustment: " + reason);
        for (const item of assessment.links?.items || [])
          line(
            "Link host: " +
              (item.host || "unavailable") +
              " · " +
              (item.status || "unknown") +
              (item.destination ? " · " + item.destination : ""),
          );
        for (const item of assessment.positive_evidence || [])
          line(
            "Supporting evidence (not proof): " +
              (item.name || "Observed") +
              (item.evidence ? " · " + item.evidence : "") +
              (item.note ? " · " + item.note : ""),
          );
        for (const item of assessment.limitations || [])
          line("Analysis limitation: " + item);
  }
  if (r.type === "SMS" && r.sms_assessment) {
    const assessment = r.sms_assessment;
    const labels = {
      link_destination: "Link and destination",
      sender_impersonation: "Sender and impersonation",
      requested_action_financial: "Sensitive or financial action",
      urgency_pressure: "Urgency and pressure",
      context_suspiciousness: "Contextual combinations",
    };
    line(assessment.summary || "Contextual SMS risk assessment", 12);
    line("Risk dimensions", 14);
    for (const [key, label] of Object.entries(labels))
      line(
        label +
          ": " +
          Number(assessment.category_scores?.[key] || 0) +
          "/100 (weight " +
          Number(assessment.weights?.[key] || 0) +
          "%)",
      );
    if (assessment.confidence)
      line(
        "Analysis confidence: " +
          assessment.confidence.label +
          " (" +
          Number(assessment.confidence.score) +
          "/100). This describes evidence matching, not legitimacy.",
      );
    if (assessment.completeness)
      line(
        "Analysis completeness: " +
          assessment.completeness.label +
          " (" +
          Number(assessment.completeness.score) +
          "/100).",
      );
    if (assessment.sender)
      line(
        "Sender assessment: " +
          assessment.sender.status +
          (assessment.sender.claimed_organization
            ? " · message mentions " +
              assessment.sender.claimed_organization
            : ""),
      );
    for (const item of assessment.links?.items || [])
      line(
        "Extracted domain: " +
          (item.host || "unparsed") +
          " · " +
          (item.status || "unknown") +
          (item.redirect_hosts?.length
            ? " · redirect parameters: " + item.redirect_hosts.join(", ")
            : ""),
      );
    for (const item of assessment.positive_evidence || [])
      line("Supporting evidence (not proof): " + item);
    for (const item of assessment.limitations || [])
      line("Analysis limitation: " + item);
  }
  if (r.type === "Software" && r.software_assessment) {
    const assessment = r.software_assessment;
    const labels = {
      source_domain: "Source and domain",
      file_authenticity: "File authenticity",
      file_characteristics: "File characteristics",
      redirect_destination: "Redirect destination",
      threat_intelligence: "Threat intelligence",
      publisher_consistency: "Publisher and brand consistency",
    };
    line(assessment.summary || "Evidence-based software risk assessment", 12);
    line("Risk dimensions", 14);
    for (const [key, label] of Object.entries(labels))
      line(
        label +
          ": " +
          Number(assessment.category_scores?.[key] || 0) +
          "/100 (weight " +
          Number(assessment.weights?.[key] || 0) +
          "%; " +
          (assessment.completeness?.dimensions?.[key]?.status || "unknown") +
          ")",
      );
    if (assessment.completeness)
      line(
        "Analysis completeness: " +
          assessment.completeness.label +
          " (" +
          Number(assessment.completeness.score) +
          "/100). Coverage is not a safety guarantee.",
      );
    if (assessment.confidence)
      line(
        "Analysis confidence: " +
          assessment.confidence.label +
          " (" +
          Number(assessment.confidence.score) +
          "/100).",
      );
    if (r.source_url) line("Submitted source URL (not opened): " + r.source_url);
    if (r.source_verification)
      line(
        "Source verification: " +
          r.source_verification.status +
          ". " +
          r.source_verification.explanation,
      );
    if (r.software_assessment?.corroboration?.high_risk_cap_applied)
      line(
        "High-risk cap applied: uncapped normalized weighted score " +
          Number(r.software_assessment.uncapped_weighted_score || 0) +
          "/100; " +
          Number(
            r.software_assessment.corroboration.strong_risk_families || 0,
          ) +
          " strong independent signal families.",
      );
    if (r.hostname) line("Parsed hostname: " + r.hostname);
    if (r.file_details) {
      line("File name: " + (r.file_details.name || "unavailable"));
      line(
        "File type: " +
          (r.file_details.type || "unavailable") +
          " · size: " +
          Number(r.file_details.size_bytes || 0) +
          " bytes",
      );
      line("SHA-256: " + (r.file_details.sha256 || "unavailable"));
      line(
        "Authenticode: " +
          (r.file_details.authenticode?.status || "not checked") +
          (r.file_details.authenticode?.signer
            ? " · signer " + r.file_details.authenticode.signer
            : ""),
      );
    }
    line(
      "Threat intelligence: " +
        (assessment.threat_intelligence?.status || "not configured") +
        ". No file or hash was sent to an external reputation service.",
    );
    for (const item of assessment.positive_evidence || [])
      line("Supporting evidence (not proof): " + item);
    for (const item of assessment.limitations || [])
      line("Analysis limitation: " + item);
  }
  if (r.type === "Website" && r.tld_policy) {
    const policyStatus = {
      approved: "Passed",
      unapproved: "Failed",
      not_applicable: "Not applicable",
    }[r.tld_policy.status] || "Unavailable";
    line(
      "Approved TLD check: " +
        policyStatus +
        (r.tld_policy.tld ? " (" + r.tld_policy.tld + ")" : "") +
        " | " +
        r.tld_policy.explanation,
    );
  }
  if (!hasObservedScore && r.basis) line(r.basis);
  if (!hasObservedScore && r.dns) line(r.dns);
  if (!hasObservedScore && r.confidence)
    line(
      "Scan confidence: " +
        r.confidence.completed +
        "/" +
        r.confidence.applicable +
        " applicable checks completed (" +
        r.confidence.percentage +
        "% inspection coverage).",
    );
  if (r.scoring && !hasObservedScore) {
    line(
      typeof r.scoring.total === "number"
      ? "Score calculation: category subtotal " +
          r.scoring.category_subtotal +
          " + corroboration bonus " +
          r.scoring.corroboration_bonus +
          " (overall score capped at 100) = " +
          r.scoring.total +
          "."
      : "Collected-evidence score: " +
          r.scoring.observed_total +
          "/100 (incomplete).",
    );
    for (const [name, points] of Object.entries(
      r.scoring.category_points || {},
    ))
      line("  " + name + ": " + points);
  }
  if (!hasObservedScore && Array.isArray(r.indicator_coverage)) {
    line("A-Z indicator framework coverage", 14);
    for (const item of r.indicator_coverage)
      line(
        item.letter +
          " · " +
          item.category +
          " · " +
          item.status +
          ": " +
          item.details,
      );
  }
  if (!hasObservedScore && Array.isArray(r.checks))
    for (const item of r.checks) {
      line(item.name + " · " + String(item.status).replaceAll("_", " "), 12);
      line(item.summary);
      for (const evidence of item.evidence || [])
        line("  " + evidence);
    }
  line("Findings", 14);
    const reportFindings =
      r.type === "Software" &&
      Array.isArray(r.software_assessment?.signals)
        ? r.software_assessment.signals
        : Array.isArray(r.findings)
          ? r.findings
          : [];
    if (!reportFindings.length) line("No risk indicators were recorded.");
    reportFindings.forEach((finding) => {
    const description =
      r.type === "Email"
        ? (finding.name || "Signal") +
          " · " +
          (finding.severity || "observation") +
          " · " +
          (finding.evidence_status === "provided_unverified"
            ? "user-supplied, not independently verified"
            : finding.evidence_status || "heuristic") +
          "   " +
          (finding.text || "")
        : r.type === "SMS"
          ? (finding.name || "Signal") +
            " · " +
            (finding.severity || "observation") +
            " · " +
            (finding.category || "unknown category") +
            " · " +
            (finding.verification_status || "heuristic") +
            "   " +
            (finding.text || "")
          : r.type === "Software"
            ? (finding.name || "Signal") +
              " · " +
              (finding.severity || "observation") +
              " · " +
              (finding.category || "unknown category") +
              " · " +
              (finding.verification_status || "heuristic") +
              " · strength " +
              Number(finding.score || 0) +
              "/100   " +
              (finding.text || "")
        : (Number(finding.points) > 0
            ? finding.points +
              " signal points · " +
              (finding.reliability || 0) +
              "% reliability"
            : finding.severity || "Observation") +
          "   " +
          finding.text;
    line(description);
    if (finding.evidence) line("Evidence: " + finding.evidence);
  });
  if (!hasObservedScore && r.reputation) line(r.reputation);
  if (!hasObservedScore) {
    r.notes.forEach((n) => line(n));
    line("Recommended action", 14);
    line(r.advice);
  }
  line("Source: " + r.source);
  line("Educational assessment limited to available evidence.");
  doc.save("CyberShield-" + r.type + "-report.pdf");
}
export function display(el, r) {
  el.innerHTML = reportHtml(r);
  el.querySelector("[data-export-pdf]").onclick = () =>
    pdf(r).catch((e) => alert(e.message));
}
