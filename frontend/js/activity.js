import { $, api, card, esc, date, options, icon } from "./common.js";
import { display, displayedCategory } from "./reports.js";
function rows(items) {
  return items.length
    ? items
        .map(
          (r) => {
            const category = displayedCategory(r);
            const score =
              typeof r.score === "number"
                ? r.score
                : r.type === "Website" && Number.isInteger(r.observed_score)
                  ? r.observed_score
                  : null;
            return (
              '<div class="listitem reportrow">' +
              (category
                ? '<span class="tag" data-risk="' +
                  esc(r.category) +
                  '">' +
                  esc(category) +
                  "</span>"
                : "") +
              "<h3>" +
                esc(r.type === "Email" ? "Email analysis" : r.target) +
                "</h3><p>" +
                esc(r.type) +
                " · " +
                esc(date(r.date)) +
                (score !== null ? " · " + score + "/100" : "") +
                '</p><button data-report="' +
                Number(r.id) +
                '">View report</button></div>'
            );
          },
        )
        .join("")
    : "<p>No scans to display.</p>";
}
function bindReports() {
  for (const b of document.querySelectorAll("[data-report]"))
    b.onclick = async () => {
      display($("#result"), await api("report?id=" + b.dataset.report));
      $("#result").scrollIntoView({ block: "start" });
    };
}
function dailyChart(days) {
  if (!days.length)
    return '<p class="empty">Your activity chart appears after your first saved check.</p>';
  const max = Math.max(...days.map((d) => d.n), 1);
  return (
    '<div class="columns">' +
    days
      .map(
        (d) =>
          '<div class="column"><strong>' +
          Number(d.n) +
          '</strong><div class="track"><b style="height:' +
          Math.max(4, (100 * d.n) / max) +
          '%"></b></div><small>' +
          esc(d.day.slice(5)) +
          "</small></div>",
      )
      .join("") +
    "</div>"
  );
}
export async function dashboard(u) {
  const [d, tips] = await Promise.all([api("dashboard"), api("tips")]);
  const s = d.summary,
    h = s.health === null ? null : Number(s.health),
    days = d.trend.slice().reverse();
  $("#greeting").textContent = "Welcome back, " + u.name.split(" ")[0] + ".";
  $(".heading .eyebrow").textContent = new Intl.DateTimeFormat(undefined, {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  }).format(new Date());
  const counts = Object.fromEntries(d.counts.map((row) => [row.type, row.n]));
  const metrics = [
    ["scan-line", "Saved checks", s.total, "history.html", "total"],
    [
      "globe",
      "Websites checked",
      counts.Website ?? 0,
      "website-detector.html",
      "web",
    ],
    [
      "mail",
      "Emails analyzed",
      counts.Email ?? 0,
      "email-detector.html",
      "email",
    ],
    [
      "layers",
      "Software checks",
      counts.Software ?? 0,
      "software-detector.html",
      "software",
    ],
    [
      "activity",
      "High-risk reports",
      s.high || 0,
      "history.html?risk=High%20risk",
      "risk",
    ],
    [
      "file-check-2",
      "Antivirus detections",
      s.detections || 0,
      "device-scanner.html",
      "device",
    ],
  ];
  const tools = [
    ["globe", "Website", "Website checker", "website-detector"],
    ["mail", "Email", "Email checker", "email-detector"],
    ["message-square-text", "SMS", "SMS scam detector", "sms-detector"],
    ["layers", "Software", "Software source", "software-detector"],
    ["file-check-2", "File", "Selected file", "device-scanner"],
    ["monitor", "Device", "Fixed drives", "device-scanner"],
  ];
  const scoreLabel =
    h === null
      ? "Run your first scored check."
      : h >= 76
        ? "Lower detected risk"
        : h >= 41
          ? "Moderate detected risk"
          : "Higher detected risk";
  const healthTone =
    h === null
      ? "var(--line)"
      : h >= 76
        ? "var(--safe)"
        : h >= 41
          ? "var(--warn)"
          : "var(--risk)";
  $("#content").innerHTML =
    '<div class="dash-metrics">' +
    metrics
      .map(
        ([i, k, v, href, tone]) =>
          '<a class="card metric" data-tone="' +
          tone +
          '" href="' +
          href +
          '"><span>' +
          icon(i) +
          " " +
          k +
          "</span><strong>" +
          Number(v) +
          "</strong></a>",
      )
      .join("") +
    '</div><div class="dashboard-grid">' +
    card(
      "Security overview",
      '<div class="overview"><div class="gauge" style="--amount:' +
        (h || 0) +
        "%;--tone:" +
        healthTone +
        '"><strong>' +
        (h ?? "—") +
        "</strong></div><div><h3>" +
        scoreLabel +
        "</h3><small>100 minus the average technical risk score of your saved checks.</small></div></div>",
    ) +
    card(
      "Scan activity",
      "<p>Volume on your latest seven active dates (UTC).</p>" +
        dailyChart(days),
    ) +
    card(
      "Tools and scan counts",
      tools
        .map(
          ([i, t, name, slug]) =>
            '<a class="toolrow" href="' +
            slug +
            '.html">' +
            icon(i) +
            "<span>" +
            name +
            "</span><strong>" +
            Number(counts[t] ?? 0) +
            "</strong></a>",
        )
        .join(""),
    ) +
    card(
      "Recent reports",
      rows(d.recent) + '<a href="history.html">View all reports</a>',
    ) +
    "</div>" +
    '<div id="result"></div><div class="twocol">' +
    card(
      "Daily security scores",
      days.some((a) => a.health !== null)
        ? days
            .filter((a) => a.health !== null)
            .map(
              (a) =>
                '<div class="trendrow"><small>' +
                esc(a.day) +
                '</small><div class="meter"><span style="width:' +
                Number(a.health) +
                '%"></span></div><strong>' +
                Number(a.health) +
                "</strong></div>",
            )
            .join("")
        : "<p>Scored checks will appear here.</p>",
    ) +
    card(
      "Safety tip",
      "<p>" +
        esc(tips[new Date().getDate() % tips.length]) +
        '</p><a href="awareness.html">Read the awareness guides</a>',
    ) +
    "</div>";
  bindReports();
}
export async function history() {
  const all = await api("history");
  $("#content").innerHTML =
    card(
      "Saved reports",
      '<p>Showing up to 500 recent checks.</p><div class="filters"><label>Search<input id="query" type="search"></label><label>Type<select id="type">' +
        options([
          "All types",
          "Website",
          "Email",
          "SMS",
          "Software",
          "File",
          "Device",
        ]) +
        '</select></label><label>Risk<select id="risk">' +
        options([
          "All risks",
          "High risk",
          "Moderate Risk",
          "Suspicious",
          "Low Risk",
          "No Known Issues Detected",
          "Unable to Verify",
          "Dangerous",
          "No known threats detected",
          "Unable to verify",
          "Lower risk",
          "Unverified",
          "Insufficient information",
        ]) +
        '</select></label><label>Date (local)<input id="day" type="date"></label></div><div id="items"></div><button id="clear">Clear history</button>',
    ) + '<div id="result"></div>';
  function filter() {
    const target = $("#query").value.toLowerCase();
    $("#items").innerHTML = rows(
      all.filter((a) => {
        const d = new Date(a.date.replace(" ", "T") + "Z");
        const day = [
          d.getFullYear(),
          String(d.getMonth() + 1).padStart(2, "0"),
          String(d.getDate()).padStart(2, "0"),
        ].join("-");
        return (
          (a.target + " " + a.type).toLowerCase().includes(target) &&
          ($("#type").selectedIndex === 0 || a.type === $("#type").value) &&
          ($("#risk").selectedIndex === 0 || a.category === $("#risk").value) &&
          (!$("#day").value || day === $("#day").value)
        );
      }),
    );
    bindReports();
  }
  const risk = new URLSearchParams(location.search).get("risk");
  if ([...$("#risk").options].some((o) => o.value === risk))
    $("#risk").value = risk;
  filter();
  $(".filters").oninput = filter;
  $("#clear").onclick = async () => {
    if (confirm("Permanently clear your saved scan reports?")) {
      await api("history", "DELETE");
      await history();
    }
  };
}
