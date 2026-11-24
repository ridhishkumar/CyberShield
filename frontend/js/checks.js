import { $, api, submit, input, area, card, esc, icon } from "./common.js";
import { display, displayedCategory } from "./reports.js";
const maxSelectedFileBytes = 200000000;
const addressField = (label, required, max = 2048) =>
  input(
    "url",
    label,
    "text",
    max,
    (required ? "required " : "") +
      'inputmode="url" autocapitalize="none" spellcheck="false" placeholder="example.in or https://example.org/path"',
  );

const dnsField =
  '<label class="switchrow"><span><strong>Check hostname availability</strong><small>Look up the hostname using your system DNS resolver.</small></span><input type="checkbox" name="dnsLookup" checked></label>';
const checks = {
  "website-detector": {
    title: "Website address",
    action: "Check website",
    endpoint: "check-url",
    hint: "Enter a domain or full web address. CyberShield performs a bounded local DNS, TLS, HTTP, redirect, and inert HTML inspection. Local/private destinations and unsafe redirects are blocked. Do not submit a URL containing private tokens. No detected indicators do not guarantee safety.",
    fields: () =>
      addressField("Website URL", true, 8192) +
      area("description", "Expected site or context (optional)", 1500),
  },
  "software-detector": {
    title: "Software and source",
    action: "Check software",
    endpoint: "check-software",
    hint: "Enter a hostname or full HTTP(S) download URL. A recognized hostname only identifies a configured publisher source; it does not verify the downloaded file or every link on that site. Pasted URLs are analyzed without being opened.",
    fields: () =>
      input("name", "Software name", "text", 120) +
      input(
        "url",
        "Download hostname or URL",
        "text",
        2048,
        'inputmode="url" autocapitalize="none" spellcheck="false" placeholder="example.org or https://example.org/download"',
      ) +
      input("publisher", "Declared publisher (optional)", "text", 120) +
      area("description", "Context (optional)", 1500) +
      '<label class="filebox">' +
      icon("file-check-2") +
      ' Optional downloaded installer<input name="file" type="file" accept=".exe,.msi,.msix,.appx,.dmg,.pkg,.deb,.rpm,.appimage,.zip,.7z,.tar,.gz"><small>One file, up to 200 MB (200,000,000 bytes). File bytes are scanned locally and are not sent to an external reputation service.</small></label>',
  },
  "email-detector": {
    title: "Email to analyze",
    action: "Analyze email",
    endpoint: "check-email",
    hint: "Paste email text for local analysis; CyberShield does not connect to Gmail. Links are checked without opening them and compared with configured official domains when a supported organization is identified. Include original headers for reply-address and reported authentication checks.",
    fields: () =>
      input(
        "sender",
        "From (optional)",
        "text",
        254,
        'autocomplete="off" placeholder="Name <sender@example.org>"',
      ) +
      input("subject", "Subject (optional)", "text", 300) +
      area("content", "Email content", 20000, "required") +
      '<details class="advanced"><summary>Original email headers (optional)</summary>' +
      area("headers", "Raw headers", 8192) +
      "</details>",
  },
  "sms-detector": {
    title: "Text message to analyze",
    action: "Analyze SMS",
    endpoint: "check-sms",
    hint: "Paste the sender exactly as shown in your SMS app, if available, and paste the message. Analysis is local; sender labels are not authenticated, and saved history omits the sender and exact evidence excerpts. No SMS permission is used.",
    fields: () =>
      input(
        "sender",
        "Sender ID or phone number (optional)",
        "text",
        128,
        'autocomplete="off" autocapitalize="characters" placeholder="Paste exactly as displayed"',
      ) + area("content", "SMS message", 5000, "required"),
  },
};
function addFinding(report, text, points) {
  if (report.findings.some((item) => item.text === text)) return false;
  report.findings.push({ text, points });
  return true;
}
async function applyFileTrust(report, file) {
  if (typeof report.trust_score === "number") return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  const extension = (file.name.split(".").pop() || "").toLowerCase();
  const prefix = new TextDecoder("latin1").decode(bytes.subarray(0, 16));
  const isPdf = prefix.startsWith("%PDF-");
  const isPe = prefix.startsWith("MZ");
  const isZip = bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 3 && bytes[3] === 4;
  const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a;
  const isJpeg = bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  const textExtensions = ["txt", "csv", "log", "md", "json", "xml", "html", "css"];
  const sample = bytes.subarray(0, Math.min(bytes.length, 4096));
  const content = new TextDecoder("latin1")
    .decode(bytes.subarray(0, 4 * 1024 * 1024))
    .toLowerCase();
  const isText = textExtensions.includes(extension) && !sample.includes(0) &&
    sample.every((value) => value === 9 || value === 10 || value === 13 || value >= 32);
  const kind = isPdf ? "PDF" : isPe ? "Windows executable" : isZip ? "ZIP container" : isPng ? "PNG image" : isJpeg ? "JPEG image" : isText ? "plain-text document" : "unrecognized file format";
  let penalty = 0;
  const mismatch =
    (extension === "pdf" && !isPdf) || (isPdf && extension !== "pdf") ||
    (extension === "png" && !isPng) || (isPng && extension !== "png") ||
    ((extension === "jpg" || extension === "jpeg") && !isJpeg) ||
    (isJpeg && !["jpg", "jpeg"].includes(extension)) ||
    (["zip", "docx", "xlsx", "pptx"].includes(extension) && !isZip) ||
    (isZip && !["zip", "docx", "xlsx", "pptx"].includes(extension)) ||
    (["exe", "dll", "scr", "sys"].includes(extension) && !isPe) ||
    (isPe && !["exe", "dll", "scr", "sys"].includes(extension)) ||
    (isText && !textExtensions.includes(extension));
  if (mismatch) {
    penalty += 35;
    addFinding(report, "The file contents do not match the selected filename extension or expected header.", 35);
  }
  if (isPdf) {
    const markers = ["/openaction", "/aa", "/launch", "/javascript", "/embeddedfile", "/richmedia"].filter((marker) => content.includes(marker)).length;
    if (markers) {
      penalty += Math.min(30, markers * 10);
      addFinding(report, "The PDF contains active-content or embedded-object markers; these can be legitimate but deserve review.", Math.min(30, markers * 10));
    }
  }
  if (isZip && ["vbaproject.bin", "word/vba", "xl/macrosheets"].some((marker) => content.includes(marker))) {
    penalty += 20;
    addFinding(report, "The archive appears to contain Office macro-related components.", 20);
  }
  if (["ps1", "vbs", "js", "jse", "hta", "bat", "cmd", "scr"].includes(extension)) {
    const markers = ["downloadstring", "frombase64string", "wscript.shell", "invoke-expression", "powershell -enc", "createobject("].filter((marker) => content.includes(marker)).length;
    if (markers) {
      penalty += Math.min(30, markers * 10);
      addFinding(report, "The script contains command-execution, download, or encoded-payload patterns.", Math.min(30, markers * 10));
    }
  }
  let trust;
  const blocked = /blocked this content under its policy/i.test(report.basis || "");
  if (report.detections === 1) trust = 0;
  else if (blocked) trust = 15;
  else if (report.detections === 0) trust = Math.max(0, 75 - penalty);
  else trust = Math.max(0, (isPe ? 30 : isText ? 55 : (isPdf || isZip || isPng || isJpeg) ? 45 : 35) - penalty);
  report.trust_score = trust;
  report.score = 100 - trust;
  report.static_penalty = penalty;
  report.notes.push("File format identified as: " + kind + ".");
  report.notes.push("Browser-side static checks examine file signature, extension consistency and selected active-content/script markers. They are not a replacement for an updated antivirus engine.");
  if (report.detections === null)
    report.basis = "No antivirus verdict was available. The displayed trust score is a limited static-only assessment, not a malware scan.";
  if (penalty >= 15 && report.category !== "High risk") report.category = "Suspicious";
  else if (report.detections === null && report.category !== "Suspicious") report.category = "Insufficient information";
}
function normalizeAddress(value) {
  let url = value.trim();
  if (!url) return "";
  if (url.startsWith("//")) url = "https:" + url;
  const authority = url.replace(/^https?:\/\//i, "").split(/[/?#]/, 1)[0];
  // Send IDNs in their DNS-compatible form while preserving the original URL structure.
  const host = authority.split("@").pop().split(":")[0];
  if (/[^\x00-\x7f]/.test(host)) {
    let hostname;
    try {
      hostname = new URL("https://" + host).hostname;
    } catch {
      throw Error("Check the spelling of the website hostname.");
    }
    const offset = url.indexOf(authority) + authority.lastIndexOf(host);
    url = url.slice(0, offset) + hostname + url.slice(offset + host.length);
  }
  return url;
}
function normalizeSoftwareAddress(value) {
  const raw = value.trim();
  if (!raw) return "";
  const explicitScheme = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  const schemeLikePrefix =
    /^[a-z][a-z0-9+.-]*:/i.test(raw) &&
    !/^[^/?#]+:\d+(?:[/?#]|$)/.test(raw);
  if (
    (explicitScheme && !/^https?$/i.test(explicitScheme[1])) ||
    (schemeLikePrefix && !explicitScheme)
  )
    throw Error("Use an HTTP(S) hostname or download URL.");
  const candidate = raw.startsWith("//")
    ? "https:" + raw
    : explicitScheme
      ? raw
      : "https://" + raw;
  try {
    const parsed = new URL(candidate);
    if (!["http:", "https:"].includes(parsed.protocol))
      throw Error("Use an HTTP(S) hostname or download URL.");
    if (!parsed.hostname)
      throw Error("Enter a hostname or complete HTTP(S) download URL.");
  } catch (error) {
    if (error.message === "Use an HTTP(S) hostname or download URL.")
      throw error;
    const authority = raw.replace(/^https?:\/\//i, "").split(/[/?#]/, 1)[0];
    if (!authority.includes("%"))
      throw Error("Enter a valid hostname or complete HTTP(S) download URL.");
  }
  return normalizeAddress(raw);
}
function validWebsiteReport(report) {
  const categories = new Set([
    "Safe",
    "Be Cautious",
    "Highly Risky",
    "High risk",
    "Moderate Risk",
    "Low Risk",
    "Suspicious",
    "No Known Issues Detected",
    "Unable to Verify",
  ]);
  const statuses = new Set([
    "complete",
    "partial",
    "unavailable",
    "blocked",
    "not_applicable",
  ]);
  const validTldPolicy =
    !report ||
    !report.tld_policy ||
    (report.tld_policy &&
      ["approved", "unapproved", "not_applicable"].includes(
        report.tld_policy.status,
      ) &&
      typeof report.tld_policy.tld === "string" &&
      typeof report.tld_policy.explanation === "string" &&
      Number.isInteger(report.tld_policy.risk_points) &&
      report.tld_policy.risk_points >= 0 &&
      report.tld_policy.risk_points <= 100 &&
      (report.tld_policy.status !== "approved" ||
        report.tld_policy.risk_points === 0) &&
      (report.tld_policy.status !== "unapproved" ||
        report.tld_policy.risk_points >= 51) &&
      (report.tld_policy.status !== "not_applicable" ||
        report.tld_policy.risk_points === 0));
  return (
    report &&
    report.type === "Website" &&
    categories.has(report.category) &&
    (report.category === "Unable to Verify"
      ? report.score === null
      : Number.isInteger(report.score) &&
        report.score >= 0 &&
        report.score <= 100) &&
    Number.isInteger(report.observed_score) &&
    report.observed_score >= 0 &&
    report.observed_score <= 100 &&
    Array.isArray(report.findings) &&
    report.findings.every(
      (finding) =>
        finding &&
        typeof finding.id === "string" &&
        typeof finding.category === "string" &&
        typeof finding.family === "string" &&
        typeof finding.severity === "string" &&
        typeof finding.text === "string" &&
        typeof finding.evidence === "string" &&
        Number.isInteger(finding.points) &&
        finding.points >= 0 &&
        finding.points <= 100 &&
        Number.isInteger(finding.reliability) &&
        finding.reliability >= 0 &&
        finding.reliability <= 100,
    ) &&
    Array.isArray(report.checks) &&
    report.checks.length === 6 &&
    report.checks.every(
      (check) =>
        check &&
        typeof check.name === "string" &&
        statuses.has(check.status) &&
        typeof check.summary === "string" &&
        Array.isArray(check.evidence) &&
        check.evidence.every((item) => typeof item === "string"),
    ) &&
    report.confidence &&
    Number.isInteger(report.confidence.completed) &&
    Number.isInteger(report.confidence.applicable) &&
    Number.isInteger(report.confidence.planned) &&
    Number.isInteger(report.confidence.percentage) &&
    report.confidence.completed >= 0 &&
    report.confidence.completed <= report.confidence.applicable &&
    report.confidence.applicable <= report.confidence.planned &&
    report.confidence.planned === 6 &&
    report.confidence.percentage >= 0 &&
    report.confidence.percentage <= 100 &&
    report.confidence.percentage ===
      (report.confidence.applicable
        ? Math.round(
            (100 * report.confidence.completed) /
              report.confidence.applicable,
          )
        : 0) &&
    report.scoring &&
    validTldPolicy &&
    report.scoring.total === report.score &&
    report.scoring.observed_total === report.observed_score &&
    ["complete_inspection", "incomplete_inspection"].includes(
      report.scoring.observed_scope,
    ) &&
    Number.isInteger(report.scoring.category_subtotal) &&
    report.scoring.category_subtotal >= 0 &&
    report.scoring.category_subtotal <= 200 &&
    Number.isInteger(report.scoring.corroboration_bonus) &&
    report.scoring.corroboration_bonus >= 0 &&
    report.scoring.corroboration_bonus <= 12 &&
    Number.isInteger(report.scoring.independent_categories) &&
    report.scoring.independent_categories >= 0 &&
    report.scoring.category_points &&
    typeof report.scoring.category_points === "object" &&
    !Array.isArray(report.scoring.category_points) &&
    Object.values(report.scoring.category_points).every(
      (points) => Number.isInteger(points) && points >= 0 && points <= 100,
    ) &&
    Array.isArray(report.indicator_coverage) &&
    report.indicator_coverage.length > 0 &&
    report.indicator_coverage.every(
      (item) =>
        item &&
        typeof item.letter === "string" &&
        typeof item.category === "string" &&
        ["checked", "partial", "not_checked", "not_used"].includes(
          item.status,
        ) &&
        typeof item.details === "string",
    ) &&
    Array.isArray(report.notes) &&
    typeof report.advice === "string" &&
    typeof report.source === "string"
  );
}
export function checker(id) {
  const check = checks[id];
  $("#content").innerHTML =
    '<div class="twocol">' +
    card(
      check.title,
      "<p>" +
        check.hint +
        '</p><form id="scan" method="post">' +
        check.fields() +
        '<div class="actions"><button class="primary">' +
        check.action +
        '</button><button type="reset">Clear</button></div><output role="status"></output></form>',
    ) +
    '<div id="result" tabindex="-1" aria-label="Scan result"></div></div>';
  if (id === "software-detector") {
    const list = document.createElement("details");
    list.className = "advanced";
    list.innerHTML = "<summary>Publisher download directory</summary><ul></ul>";
    $("#scan").after(list);
    list.ontoggle = async () => {
      if (!list.open || list.querySelector("li")) return;
      try {
        const sources = await api("software-sources");
        list.querySelector("ul").innerHTML = sources
          .map(
            (s) =>
              '<li><a rel="noopener noreferrer" target="_blank" href="' +
              esc(s.url) +
              '">' +
              esc(s.product) +
              "</a></li>",
          )
          .join("");
      } catch (error) {
        list.querySelector("ul").textContent = error.message;
      }
    };
  }
  const form = $("#scan");
  const result = $("#result");
  let generation = 0;
  form.onreset = () => {
    generation++;
    result.replaceChildren();
    form.querySelector("output").textContent = "";
  };
  if (id === "website-detector")
    form.addEventListener("input", () => {
      if (!form.querySelector("button.primary").disabled) return;
      generation++;
      result.replaceChildren();
      form.querySelector("output").textContent =
        "Inputs changed; the pending scan result will be discarded.";
    });
  submit(form, async (data) => {
    const current = ++generation;
    result.replaceChildren();
    let report;
    if (id === "website-detector")
      form.querySelector("output").textContent =
        "Inspecting the submitted URL with CyberShield's local engine…";
    if ("url" in data) {
      data.url =
        id === "software-detector"
          ? normalizeSoftwareAddress(data.url)
          : normalizeAddress(data.url);
      data.dnsLookup = data.dnsLookup === "on";
    }
    if (id === "software-detector") {
      data.name = data.name.trim();
      if (!data.name && !data.url)
        throw Error("Enter a software name or a download URL.");
      const file = data.file;
      delete data.file;
      if (file && file.name && file.size === 0)
        throw Error("The selected file is empty. Choose a nonempty installer.");
      if (file && file.name && file.size > maxSelectedFileBytes)
        throw Error(
          "The selected file is larger than 200 MB (200,000,000 bytes). Use the download URL field to check its source; this is a URL check, not a file scan.",
        );
      if (file && file.name) {
        const query = new URLSearchParams();
        for (const key of ["name", "url", "publisher", "description"])
          if (data[key]) query.set(key, data[key]);
        report = await api(
          "check-software-file?" + query.toString(),
          "POST",
          file,
        );
      } else {
        report = await api(check.endpoint, "POST", data);
      }
    } else {
      try {
        report = await api(check.endpoint, "POST", data);
      } catch (error) {
        if (id === "website-detector")
          throw Error("Unable to verify this URL. " + error.message);
        throw error;
      }
    }
    if (current !== generation)
      return id === "website-detector"
        ? "Inputs changed during the scan; its result was discarded."
        : "";
    if (id === "website-detector" && !validWebsiteReport(report))
      throw Error(
        "The running server returned an incompatible Website report. Close old CyberShield server windows, start the updated copy, and try again.",
      );
    display(result, report);
    result.focus({ preventScroll: true });
    if (matchMedia("(max-width: 800px)").matches)
      result.scrollIntoView({ block: "start" });
    if (id === "website-detector") {
      if (report.category === "Unable to Verify") {
        const category = displayedCategory(report);
        return (
          (category ? category + " — " : "") +
          report.observed_score +
          "/100"
        );
      }
      return displayedCategory(report) + ".";
    }
    return "Analysis complete.";
  });
}
export async function device() {
  $("#content").innerHTML =
    '<div class="twocol">' +
    card(
      "Scan a file or application",
      '<p>Inspect file bytes and request a malware verdict from ClamAV or the Windows antimalware provider.</p><form id="fileform"><label class="filebox">' +
        icon("file-check-2") +
        ' Select a file<input type="file" required><small>One file, up to 200 MB (' +
        maxSelectedFileBytes.toLocaleString() +
        ' bytes)</small></label><small id="meta"></small><button class="primary">Scan selected file</button><output role="status"></output></form><div id="file-result" tabindex="-1" aria-label="Selected file report"></div>',
    ) +
    "</div>";
  const file = $("#fileform input");
  file.onchange = () => {
    $("#file-result").replaceChildren();
    $("#fileform output").textContent = "";
    const f = file.files[0];
    $("#meta").textContent = f
      ? f.name +
        " · " +
        (f.type || "Unknown type") +
        " · " +
        f.size.toLocaleString() +
        " bytes (" +
        (f.size / 1000000).toFixed(2) +
        " MB)"
      : "";
  };
  const form = $("#fileform");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button.primary");
    const output = form.querySelector("output");
    if (button.disabled) return;
    const f = file.files[0];
    if (!f) {
      output.textContent = "Select a file to scan.";
      return;
    }
    if (f.size === 0) {
      output.textContent = "The selected file is empty. Choose a nonempty file.";
      return;
    }
    if (f.size > maxSelectedFileBytes) {
      output.innerHTML =
        'The selected file is larger than 200 MB (' +
        maxSelectedFileBytes.toLocaleString() +
        ' bytes). Use <a href="/pages/software-detector.html">Software Detector</a> to check its download source; this is a URL check, not a file scan.';
      return;
    }
    button.disabled = true;
    output.textContent = "Scanning file…";
    $("#file-result").replaceChildren();
    try {
      const report = await api("check-file", "POST", f);
      if (file.files[0] !== f) return;
      await applyFileTrust(report, f);
      if (file.files[0] !== f) return;
      display($("#file-result"), report);
      $("#file-result").focus({ preventScroll: true });
      output.textContent = "File report ready.";
    } catch (e) {
      output.textContent = e.message;
    } finally {
      button.disabled = false;
    }
  });
}
