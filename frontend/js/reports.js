import { esc, icon, date } from "./common.js";
export function reportHtml(r) {
  const tone =
    { "High risk": "high", Suspicious: "moderate", "Lower risk": "low" }[
      r.category
    ] || "unknown";
  const title = r.type === "Email" ? "Email analysis" : r.target;
  const hasTrustScore = typeof r.trust_score === "number";
  const trustScore = hasTrustScore ? r.trust_score : null;
  const hasScore = typeof r.score === "number";
  const findings = r.findings
    .map(
      (f) =>
        "<li><strong>+" +
        Number(f.points) +
        "</strong><span>" +
        esc(f.text) +
        "</span></li>",
    )
    .join("");
  return (
    '<section class="card result risk-' +
    tone +
    '"><div class="resulthead"><span class="tag">' +
    esc(r.category) +
    "</span><small>" +
    esc(date(r.date)) +
    "</small></div><h2>" +
    esc(title) +
    "</h2>" +
    (trustScore !== null
      ? '<div class="risknumber"><strong>' +
        trustScore +
        '</strong><small>/ 100 trust score</small></div><div class="meter"><span style="width:' +
        trustScore +
        '%"></span></div>' +
        (hasScore ? '<small>Detected risk indicators: ' + r.score + '/100</small>' : '')
      : '<p class="report-basis">Trust score unavailable for this saved report. Run a new analysis to generate one.</p>') +
    (r.basis ? '<p class="report-basis">' + esc(r.basis) + "</p>" : "") +
    (r.dns ? "<p>" + esc(r.dns) + "</p>" : "") +
    (["Website", "Software"].includes(r.type)
      ? "<h3>Score breakdown</h3>"
      : "<h3>Detected indicators</h3>") +
    (findings
      ? '<ul class="evidence">' + findings + "</ul>"
      : "<p>" +
        (hasScore
          ? "No local rules raised a warning."
          : r.basis
            ? "See the evidence below for the checks completed."
            : "See the scan summary below.") +
        "</p>") +
    '<div class="recommend"><h3>Recommended action</h3><p>' +
    esc(r.advice) +
    '</p></div><details class="advanced"' +
    (["Website", "Software", "Email", "SMS", "File"].includes(r.type)
      ? " open"
      : "") +
    "><summary>Evidence and limitations</summary>" +
    (r.reputation ? "<p>" + esc(r.reputation) + "</p>" : "") +
    r.notes.map((n) => "<p>" + esc(n) + "</p>").join("") +
    "<small>Source · " +
    esc(r.source) +
    "</small></details><button data-export-pdf>" +
    icon("download") +
    " Download PDF</button></section>"
  );
}
let library;
export async function pdf(r) {
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
    "Assessment: " +
      r.category +
      (typeof r.trust_score === "number"
        ? " | Trust score: " + r.trust_score + "/100"
        : " | Trust score unavailable for this saved report"),
  );
  if (r.basis) line(r.basis);
  if (r.dns) line(r.dns);
  line("Findings", 14);
  if (!r.findings.length) line("No rule indicators recorded.");
  r.findings.forEach((f) => line("+" + f.points + "   " + f.text));
  if (r.reputation) line(r.reputation);
  r.notes.forEach((n) => line(n));
  line("Recommended action", 14);
  line(r.advice);
  line("Source: " + r.source);
  line("Educational assessment limited to available evidence.");
  doc.save("CyberShield-" + r.type + "-report.pdf");
}
export function display(el, r) {
  el.innerHTML = reportHtml(r);
  el.querySelector("[data-export-pdf]").onclick = () =>
    pdf(r).catch((e) => alert(e.message));
}
