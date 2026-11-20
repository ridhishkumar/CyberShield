import { $, api, submit, input, area, card, esc, icon } from "./common.js";
import { display } from "./reports.js";
const addressField = (label, required) =>
  input(
    "url",
    label,
    "text",
    2048,
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
    hint: "Enter a domain or full web address. CyberShield checks for deceptive wording and compares the address with known publisher locations.",
    fields: () =>
      addressField("Website URL", true) +
      area("description", "Expected site or context (optional)", 1500) +
      dnsField,
  },
  "software-detector": {
    title: "Software and source",
    action: "Check software",
    endpoint: "check-software",
    hint: "Enter a software name or a download address. Add both to compare the product with its distribution source.",
    fields: () =>
      input("name", "Software name", "text", 120) +
      addressField("Download URL", false) +
      input("publisher", "Declared publisher (optional)", "text", 120) +
      area("description", "Context (optional)", 1500) +
      dnsField,
  },
  "email-detector": {
    title: "Email to analyze",
    action: "Analyze email",
    endpoint: "check-email",
    hint: "Paste the email as plain text. Include the original headers to check reply addresses and reported authentication results.",
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
    hint: "Enter the number shown on the text, if available, and paste the message. History saves the assessment without the number or message.",
    fields: () =>
      input(
        "phone",
        "Sender phone number (optional)",
        "tel",
        32,
        'autocomplete="off" placeholder="+1 202 555 0147"',
      ) + area("content", "SMS message", 5000, "required"),
  },
};
const urlShorteners = new Set([
  "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy",
  "shorturl.at", "rebrand.ly", "ow.ly", "buff.ly",
]);
const riskSuffixes = [
  ".zip", ".mov", ".click", ".top", ".work", ".support", ".rest",
  ".country", ".gq", ".tk", ".ml", ".cf", ".xyz", ".online", ".site", ".live",
];
function addFinding(report, text, points) {
  if (report.findings.some((item) => item.text === text)) return false;
  report.findings.push({ text, points });
  return true;
}
function inspectUrl(raw) {
  const findings = [];
  let parsed;
  try {
    parsed = new URL(raw.startsWith("www.") ? "https://" + raw : raw);
  } catch {
    return findings;
  }
  const host = parsed.hostname.toLowerCase();
  const labels = host.split(".").filter(Boolean);
  if (urlShorteners.has(host))
    findings.push(["The address uses a URL-shortening service, which hides the final destination.", 20]);
  if (riskSuffixes.some((suffix) => host.endsWith(suffix)))
    findings.push(["The domain uses a suffix sometimes seen in abuse-prone registrations; this alone does not make it malicious.", 8]);
  if (labels.length >= 5)
    findings.push(["The hostname has an unusually deep subdomain structure.", 12]);
  if ((parsed.href.match(/%/g) || []).length >= 5)
    findings.push(["The URL contains many percent-encoded characters, making its destination harder to read.", 10]);
  if ((parsed.href.match(/&/g) || []).length >= 8)
    findings.push(["The URL contains an unusually complex query string.", 8]);
  if (/(login|signin|verify|account|password|payment|wallet)/i.test(parsed.pathname) && (host.includes("-") || labels.length >= 4))
    findings.push(["A sensitive account-related path is combined with a complex hostname.", 12]);
  return findings;
}
function applyWebOrEmailTrust(report, id, data) {
  if (typeof report.trust_score === "number") return;
  let extraRisk = 0;
  const urls = [];
  if (data.url) urls.push(data.url);
  if (id === "email-detector") {
    const matches = data.content.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
    for (const value of matches.slice(0, 32))
      urls.push(value.replace(/[),.;!?]+$/, ""));
  }
  const seen = new Set();
  for (const raw of urls) {
    for (const [text, points] of inspectUrl(raw)) {
      if (!seen.has(text)) {
        if (addFinding(report, text, points)) extraRisk += points;
        seen.add(text);
      }
    }
  }
  const baseRisk = Number.isFinite(report.score)
    ? report.score
    : report.findings.reduce((sum, item) => sum + Number(item.points || 0), 0);
  let evidencePenalty = 0;
  if (id === "website-detector" || id === "software-detector") {
    evidencePenalty = report.basis && /matches a location in the publisher reference|match a publisher reference/i.test(report.basis) ? 15 : 30;
    if (!data.url) evidencePenalty = 35;
  } else {
    evidencePenalty = (data.sender ? 12 : 20) + (data.headers ? 0 : 18);
    if (data.headers) {
      const allPass = ["spf", "dkim", "dmarc"].every((key) =>
        new RegExp("\\b" + key + "\\s*=\\s*pass\\b", "i").test(data.headers),
      );
      if (!allPass) evidencePenalty += 8;
    }
  }
  const risk = Math.min(100, baseRisk + extraRisk);
  report.score = risk;
  report.trust_score = Math.max(0, 100 - risk - evidencePenalty);
  report.confidence_penalty = evidencePenalty;
  report.notes.push("Trust score = 100 minus detected risk indicators and an evidence-coverage penalty. It is a screening estimate, not a probability or guarantee.");
  if (id === "website-detector" || id === "software-detector")
    report.notes.push("The browser-side checks inspect the submitted URL structure only. They do not visit the site or verify its live content, domain ownership or age.");
  else
    report.notes.push("Email sender identity and supplied authentication headers are not independently authenticated by this local analysis.");
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
  const isText = textExtensions.includes(extension) && !sample.includes(0) &&
    sample.every((value) => value === 9 || value === 10 || value === 13 || value >= 32);
  const kind = isPdf ? "PDF" : isPe ? "Windows executable" : isZip ? "ZIP container" : isPng ? "PNG image" : isJpeg ? "JPEG image" : isText ? "plain-text document" : "unrecognized file format";
  const content = new TextDecoder("latin1").decode(bytes).toLowerCase();
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
  submit(form, async (data) => {
    const current = ++generation;
    result.replaceChildren();
    if ("url" in data) {
      data.url = normalizeAddress(data.url);
      data.dnsLookup = data.dnsLookup === "on";
    }
    if (id === "software-detector") {
      data.name = data.name.trim();
      if (!data.name && !data.url)
        throw Error("Enter a software name or a download URL.");
    }
    const report = await api(check.endpoint, "POST", data);
    if (current !== generation) return;
    if (id === "website-detector" || id === "software-detector" || id === "email-detector")
      applyWebOrEmailTrust(report, id, data);
    display(result, report);
    result.focus({ preventScroll: true });
    if (matchMedia("(max-width: 800px)").matches)
      result.scrollIntoView({ block: "start" });
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
        ' Select a file<input type="file" required><small>One file, up to 8 MiB</small></label><small id="meta"></small><button class="primary">Scan selected file</button><output role="status"></output></form><div id="file-result" tabindex="-1" aria-label="Selected file report"></div>',
    ) +
    card(
      "Complete device scan",
      '<p>Scan accessible files on fixed Windows drives with the installed helper.</p><p id="progress" role="status" aria-live="polite">Checking the scanner connection…</p><div class="actions"><button id="full" class="primary" hidden>Scan fixed drives</button><button id="refresh">Check connection</button></div><details id="alternative"><summary>Other ways to scan</summary><p>On Windows, open Windows Security, choose Virus &amp; threat protection → Scan options → Full scan. Review the results in Windows Security.</p><p>To see results here, install ClamAV, update its signatures and start clamd on loopback port 3310. See the project README for setup.</p></details>',
    ) +
    '</div><section id="result"></section>';
  const file = $("#fileform input"),
    full = $("#full"),
    refresh = $("#refresh"),
    progress = $("#progress");
  let timer;
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
        " bytes"
      : "";
  };
  submit($("#fileform"), async () => {
    const f = file.files[0];
    if (!f || !f.size || f.size > 8388608)
      throw Error("Select a nonempty file up to 8 MiB.");
    $("#file-result").replaceChildren();
    const report = await api("check-file", "POST", f);
    if (file.files[0] !== f) return;
    await applyFileTrust(report, f);
    if (file.files[0] !== f) return;
    display($("#file-result"), report);
    $("#file-result").focus({ preventScroll: true });
    return "File report ready.";
  });
  function showState(s) {
    clearTimeout(timer);
    const running = s.state === "running";
    full.hidden = !s.enabled || running || s.busy;
    $("#alternative").open = !s.enabled && !running;
    if (running) {
      progress.textContent =
        "Scanning fixed drives · " +
        s.checked +
        " checked · " +
        s.detected +
        " detections · " +
        s.errors +
        " skipped or failed.";
    } else if (s.state === "done") {
      progress.textContent = "Scan complete. Your report is below.";
      display($("#result"), s.report);
    } else if (s.state === "failed") progress.textContent = s.message;
    else if (s.busy)
      progress.textContent = "Another scan is using the local engine.";
    else if (!s.fileReady)
      progress.textContent =
        "Full-drive scan unavailable while ClamAV is offline. You can still inspect an individual file.";
    else if (!s.helperReady)
      progress.textContent =
        "File scanning is ready. Full scans require the Windows helper.";
    else
      progress.textContent = "Local ClamAV and the Windows helper are ready.";
    if (running || s.busy) timer = setTimeout(poll, 2000);
  }
  async function poll() {
    clearTimeout(timer);
    refresh.disabled = true;
    try {
      showState(await api("device"));
    } catch (e) {
      full.hidden = true;
      progress.textContent = e.message + " Use Check connection to resume.";
    } finally {
      refresh.disabled = false;
    }
  }
  full.onclick = async () => {
    if (
      !confirm(
        "Start a local antivirus scan of accessible files on all fixed drives?",
      )
    )
      return;
    full.disabled = refresh.disabled = true;
    progress.textContent = "Starting the local scanner…";
    try {
      showState(await api("device", "POST", { consent: true }));
    } catch (e) {
      progress.textContent = e.message;
    } finally {
      full.disabled = refresh.disabled = false;
    }
  };
  refresh.onclick = poll;
  await poll();
}
