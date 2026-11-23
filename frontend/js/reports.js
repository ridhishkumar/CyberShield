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
    report.observed_score >= 50
  )
    return "Highly Risky";
  if (report.category === "Unable to Verify") return "";
  return report.category;
}

export function reportHtml(r) {
  const category = displayedCategory(r);
  const tone =
    category === "Highly Risky"
      ? "high"
      : (
    {
      "High risk": "high",
      "Moderate Risk": "moderate",
      Suspicious: "moderate",
      "Low Risk": "low",
      "No Known Issues Detected": "low",
      "Insufficient information": "unknown",
      "Listed source": "unknown",
      "Unable to Verify": "unknown",
      Dangerous: "high",
      "No known threats detected": "low",
      "Unable to verify": "unknown",
      "Lower risk": "low",
      Unverified: "unknown",
    }[category] || "unknown");
  const title = r.type === "Email" ? "Email analysis" : r.target;
  const isWebsite = r.type === "Website";
  const isSoftware = r.type === "Software";
  const hasTrustScore = typeof r.trust_score === "number";
  const trustScore = hasTrustScore ? r.trust_score : null;
  const hasScore = typeof r.score === "number";
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
  const findings = r.findings
    .map(
      (finding) =>
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
        "</span></li>",
    )
    .join("");
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
    (isWebsite && hasScore
      ? '<div class="risknumber"><strong>' +
        r.score +
        '</strong><small>/ 100 risk score</small></div><div class="meter"><span style="width:' +
        r.score +
        '%"></span></div>'
      : isSoftware && hasScore
        ? '<div class="risknumber"><strong>' +
          r.score +
          '</strong><small>/ 100 risk score</small></div><div class="meter"><span style="width:' +
          r.score +
          '%"></span></div>'
      : hasObservedScore
        ? '<div class="risknumber"><strong>' +
          Number(r.observed_score) +
          '</strong><small>/ 100 risk score</small></div><div class="meter"><span style="width:' +
          Number(r.observed_score) +
          '%"></span></div>'
      : trustScore !== null
      ? '<div class="risknumber"><strong>' +
        trustScore +
        '</strong><small>/ 100 trust score</small></div><div class="meter"><span style="width:' +
        trustScore +
        '%"></span></div>' +
        (hasScore ? '<small>Detected risk indicators: ' + r.score + '/100</small>' : '')
      : isWebsite
        ? '<p class="report-basis">No score could be calculated from the available evidence.</p>'
        : '<p class="report-basis">Trust score unavailable for this saved report. Run a new analysis to generate one.</p>') +
    tldPolicyHtml +
    (!hasObservedScore && r.basis
      ? '<p class="report-basis">' + esc(r.basis) + "</p>"
      : "") +
    (!hasObservedScore && r.dns ? "<p>" + esc(r.dns) + "</p>" : "") +
    confidenceHtml +
    scoringHtml +
    (!isWebsite && ["Software"].includes(r.type)
      ? "<h3>Score breakdown</h3>"
      : "<h3>Detected indicators</h3>") +
    (findings
      ? '<ul class="evidence">' + findings + "</ul>"
      : "<p>" +
        (hasScore
          ? isWebsite
            ? "No risk indicators contributed points."
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
  line("Target: " + (r.type === "Email" ? "Email analysis" : r.target));
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
        : typeof r.trust_score === "number"
        ? " | Trust score: " + r.trust_score + "/100"
        : " | Trust score unavailable for this saved report"),
  );
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
  if (!r.findings.length) line("No rule indicators recorded.");
  r.findings.forEach((finding) => {
    line(
      (Number(finding.points) > 0
        ? finding.points +
          " signal points · " +
          (finding.reliability || 0) +
          "% reliability"
        : finding.severity || "Observation") +
        "   " +
        finding.text,
    );
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
