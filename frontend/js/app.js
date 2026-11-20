import { $, api, esc, icon, brand, theme, date } from "./common.js";
import { navigation, topics } from "./catalog.js";
import { assistant } from "./assistant.js";
import { dashboard, history } from "./activity.js";
import { checker, device } from "./checks.js";
import { settings, profile, logout } from "./account.js";
import { news } from "./news.js";
const id = document.body.dataset.page;
async function run() {
  let user;
  try {
    user = await api("auth/me");
  } catch (e) {
    if (e.status !== 401) throw e;
    location.replace("/login.html");
    return;
  }
  const shell = $("#shell");
  document.body.classList.add("signed");
  const settingsData = await api("settings");
  theme(settingsData.theme);
  const isCurrent = (page) => (page === id ? ' aria-current="page"' : "");
  const features = navigation
    .map(
      ([slug, label, glyph]) =>
        `<a data-feature="${slug}" href="/pages/${slug}.html"${isCurrent(slug)}>
      ${icon(glyph)}<span>${label}</span>
    </a>`,
    )
    .join("");
  shell.innerHTML = `
    <header class="top">
      <div class="top-brand">
        <button class="mobiletoggle" id="menu" aria-label="Toggle navigation" aria-controls="features" aria-expanded="false">${icon("menu")}</button>
        ${brand}
      </div>
      <nav class="account-nav" aria-label="Account">
        <button id="notices" aria-label="Notifications" aria-controls="popover" aria-expanded="false">${icon("bell")}</button>
        <a href="/pages/settings.html" aria-label="Settings"${isCurrent("settings")}>${icon("settings")}<span>Settings</span></a>
        <div class="profile-controls">
          <a href="/pages/profile.html" aria-label="My profile"${isCurrent("profile")}>${icon("user-round")}<span>Profile</span></a>
          <button id="person" aria-label="Account menu" aria-controls="popover" aria-expanded="false">${icon("chevron-down")}</button>
        </div>
      </nav>
    </header>
    <nav id="features" class="side" aria-label="Features">${features}</nav>
    <div id="popover" class="popover" hidden></div>`;
  const menu = $("#menu");
  menu.onclick = () => {
    menu.setAttribute("aria-expanded", $(".side").classList.toggle("open"));
  };
  const pop = $("#popover");
  const person = $("#person");
  const notices = $("#notices");
  function closePopover() {
    pop.hidden = true;
    person.setAttribute("aria-expanded", "false");
    notices.setAttribute("aria-expanded", "false");
  }
  function show(k, html) {
    const hide = pop.dataset.kind === k && !pop.hidden;
    closePopover();
    if (hide) return;
    pop.innerHTML = html;
    pop.dataset.kind = k;
    pop.hidden = false;
    (k === "account" ? person : notices).setAttribute("aria-expanded", "true");
  }
  person.onclick = () => {
    show(
      "account",
      `<strong class="menu-name">${esc(user.username)}</strong>
      <a href="/pages/profile.html">My profile</a>
      <a href="/pages/settings.html#prefs">Theme</a>
      <a href="/pages/settings.html">Settings</a>
      <button id="signout">Sign out</button>`,
    );
    if (!pop.hidden) $("#signout").onclick = logout;
  };
  document.addEventListener("click", (event) => {
    if (!event.target.closest("#popover, #person, #notices")) closePopover();
    if (!event.target.closest("#features, #menu")) {
      $(".side").classList.remove("open");
      menu.setAttribute("aria-expanded", "false");
    }
  });
  $("#notices").onclick = async () => {
    const logs = await api("notifications");
    show(
      "notices",
      "<h3>Notifications</h3>" +
        logs
          .map(
            (n) =>
              '<div class="listitem">' +
              (n.seen ? "" : "<b>New · </b>") +
              esc(n.message) +
              "<br><small>" +
              esc(date(n.date)) +
              "</small></div>",
          )
          .join("") +
        (logs.length
          ? '<button id="read">Mark all as read</button>'
          : "<p>No notifications yet.</p>"),
    );
    if ($("#read"))
      $("#read").onclick = async () => {
        await api("notifications", "PUT");
        closePopover();
      };
  };
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (!pop.hidden)
        (pop.dataset.kind === "account" ? person : notices).focus();
      closePopover();
      if ($(".side").classList.contains("open")) menu.focus();
      $(".side").classList.remove("open");
      menu.setAttribute("aria-expanded", "false");
    }
  });
  assistant();
  if (id === "dashboard") await dashboard(user);
  else if (id === "history") await history();
  else if (id === "device-scanner") await device();
  else if (id.endsWith("detector")) checker(id);
  else if (id === "news") await news();
  else if (id === "profile") await profile(user);
  else if (id === "settings") await settings();
  else if (id === "awareness")
    $("#content").innerHTML =
      '<div class="cards">' +
      topics
        .map(
          ([p, t, i, desc]) =>
            '<a class="card topic" href="/' +
            p +
            '.html"><span class="tile">' +
            icon(i) +
            "</span><h2>" +
            t +
            "</h2><p>" +
            desc +
            "</p>Read guide →</a>",
        )
        .join("") +
      "</div>";
}
run().catch((e) => ($("#status").textContent = e.message));
window.addEventListener("unhandledrejection", (e) => {
  $("#status").textContent =
    e.reason?.message || "Action could not be completed.";
});
