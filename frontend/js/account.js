import {
  $,
  api,
  card,
  input,
  submit,
  esc,
  date,
  theme,
  options,
  icon,
} from "./common.js";
export async function profile(user) {
  $("#content").innerHTML =
    '<div class="twocol">' +
    card(
      "Account details",
      "<p>" +
        esc(user.email) +
        " · " +
        esc(user.status) +
        "</p><small>Registered " +
        esc(date(user.created)) +
        '</small><form id="profile">' +
        input("name", "Full name", "text", 80, "required") +
        input(
          "username",
          "Username",
          "text",
          32,
          'required pattern="[A-Za-z0-9_]{3,32}"',
        ) +
        '<button class="primary">Save profile</button><output></output></form>',
    ) +
    card(
      "Change password",
      '<form id="password">' +
        input(
          "current",
          "Current password",
          "password",
          128,
          'required autocomplete="current-password"',
        ) +
        input(
          "password",
          "New password",
          "password",
          128,
          'minlength="12" required autocomplete="new-password"',
        ) +
        input(
          "confirm",
          "Confirm new password",
          "password",
          128,
          'required autocomplete="new-password"',
        ) +
        "<p>Changing your password signs out all sessions.</p><button>Change password</button><output></output></form>",
    ) +
    "</div>" +
    deletion();
  const form = $("#profile");
  form.elements.name.value = user.name;
  form.elements.username.value = user.username;
  submit(form, async (d) => {
    await api("profile", "PUT", d);
    return "Profile saved.";
  });
  submit($("#password"), async (d) => {
    if (d.password !== d.confirm) throw Error("Both new passwords must match.");
    await api("profile/change-password", "POST", d);
    location.assign("/login.html");
  });
  bindDelete();
}
const deletion = () =>
  card(
    "Delete account",
    '<details><summary>Permanently delete this account</summary><p>Deletes this account, sessions, notifications and saved reports.</p><form id="delete">' +
      input("current", "Current password", "password", 128, "required") +
      '<button class="danger">Delete my account</button><output></output></form></details>',
  );
function bindDelete() {
  submit($("#delete"), async (d) => {
    if (confirm("Permanently delete your account and all its records?")) {
      await api("profile", "DELETE", d);
      location.assign("/login.html");
    }
  });
}
export async function settings() {
  const [s, sessions] = await Promise.all([api("settings"), api("sessions")]);
  const prefs = {
    security: "High-risk alerts",
    scans: "Scan completion notices",
    general: "Account activity notices",
    history: "Save future scans to history",
  };
  function toggle(k, description) {
    return (
      '<label class="switchrow"><span><strong>' +
      prefs[k] +
      "</strong><small>" +
      description +
      '</small></span><input role="switch" type="checkbox" name="' +
      k +
      '" ' +
      (s[k] ? "checked" : "") +
      "></label>"
    );
  }
  $("#content").innerHTML =
    '<div class="settings-grid"><form class="card settingsform" id="prefs"><h2>' +
    icon("sun") +
    ' Appearance</h2><label>Workspace theme<select name="theme">' +
    options(["system", "dark", "light"]) +
    "</select></label><hr><h2>" +
    icon("bell") +
    " Notifications</h2>" +
    toggle("security", "When a saved check raises a high-risk alert.") +
    toggle("scans", "When a scan completes.") +
    toggle("general", "Sign-in and account activity.") +
    "<hr><h2>" +
    icon("history") +
    " Privacy</h2>" +
    toggle("history", "Include new reports in your history and dashboard.") +
    '<button class="primary">Save settings</button><output role="status"></output></form><div>' +
    card(
      "Active sessions",
      sessions
        .map(
          (r) =>
            '<div class="sessionitem">' +
            icon("monitor") +
            "<div><strong>" +
            (r.current ? "This session" : "Another session") +
            "</strong><small>Signed in " +
            esc(date(r.created)) +
            "</small><small>Expires " +
            esc(date(r.expires)) +
            "</small></div></div>",
        )
        .join("") + '<button id="revoke">Sign out other sessions</button>',
    ) +
    card(
      "Account controls",
      '<div class="settings-actions"><a href="/pages/profile.html#password">Change password</a><button id="clear">Clear scan history</button><button id="logout">Sign out</button></div>',
    ) +
    deletion() +
    "</div></div>";
  $("#prefs").elements.theme.value = s.theme;
  submit($("#prefs"), async (d, f) => {
    for (const k of Object.keys(prefs)) d[k] = f.elements[k].checked;
    await api("settings", "PUT", d);
    theme(d.theme);
    return "Preferences saved.";
  });
  $("#revoke").onclick = async () => {
    await api("sessions", "DELETE");
    await settings();
    $("#status").textContent = "Other sessions signed out.";
  };
  $("#clear").onclick = async () => {
    if (confirm("Clear all your saved scan reports?")) {
      await api("history", "DELETE");
      $("#status").textContent = "History cleared.";
    }
  };
  $("#logout").onclick = logout;
  bindDelete();
}
export async function logout() {
  await api("auth/logout", "POST");
  location.assign("/login.html");
}
