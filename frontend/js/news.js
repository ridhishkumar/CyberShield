import { $, api, card, esc, options } from "./common.js";
export async function news() {
  const feed = await api("news"),
    xml = new DOMParser().parseFromString(feed.xml, "application/xml");
  const items = [...xml.querySelectorAll("item")].slice(0, 30);
  const cats = [
    "All topics",
    "Cybersecurity",
    "Technology",
    "Data breaches",
    "Software security",
    "AI and security",
    "Online scams and threats",
  ];
  $("#content").innerHTML =
    '<p class="sub">The Hacker News · ' +
    (feed.retrieved
      ? "Feed retrieved " + new Date(feed.retrieved * 1000).toLocaleString()
      : "Feed currently unavailable") +
    '</p><label>Filter headlines<select id="category">' +
    options(cats) +
    '</select></label><div class="cards" id="newslist"></div>';
  function render() {
    const filters = [
      /.*/,
      /.*/,
      /tech|platform|cloud|device/i,
      /breach|leak|stolen|expos/i,
      /patch|flaw|vulnerab|software/i,
      /\bAI\b|artificial intelligence|model/i,
      /scam|phish|fraud|threat/i,
    ];
    let html = "";
    for (const item of items) {
      const t = (k) => item.querySelector(k)?.textContent || "";
      let url;
      try {
        url = new URL(t("link"));
      } catch {
        continue;
      }
      if (url.protocol !== "https:") continue;
      const title = t("title"),
        summary = t("description")
          .replace(/<[^>]*>/g, " ")
          .replace(/\s+/g, " ")
          .trim();
      if (!filters[$("#category").selectedIndex].test(title + " " + summary))
        continue;
      html += card(
        esc(title),
        "<small>" +
          esc(t("pubDate")) +
          " · The Hacker News</small><p>" +
          esc(summary.slice(0, 260)) +
          '</p><a target="_blank" rel="noopener noreferrer" href="' +
          esc(url.href) +
          '">Read article ↗</a>',
      );
    }
    $("#newslist").innerHTML =
      html ||
      card(
        "No headlines available",
        '<p>Browse the publisher for current stories.</p><a href="https://thehackernews.com/" target="_blank" rel="noopener noreferrer">The Hacker News ↗</a>',
      );
  }
  render();
  $("#category").onchange = render;
}
