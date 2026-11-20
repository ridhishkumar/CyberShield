import { $, api, submit, icon } from "./common.js";
const page = document.body.dataset.page;
if (page === "login" && new URLSearchParams(location.search).has("registered"))
  $("#registered").hidden = false;
for (const b of document.querySelectorAll(".reveal"))
  b.onclick = () => {
    const input = b.previousElementSibling;
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    b.setAttribute("aria-label", show ? "Hide password" : "Show password");
    b.innerHTML = icon(show ? "eye-off" : "eye");
  };
if (page === "signup")
  $("#authform").elements.password.oninput = (e) => {
    $("#strength").textContent =
      e.target.value.length >= 16
        ? "Long passphrase"
        : e.target.value.length >= 12
          ? "Minimum length met"
          : "Use at least 12 characters.";
  };
submit($("#authform"), async (data) => {
  if (page === "signup" && data.password !== data.confirm)
    throw Error("The passwords must match.");
  const r = await api(
    "auth/" + (page === "signup" ? "register" : page),
    "POST",
    data,
  );
  if (page === "forgot-password") return r.message;
  location.replace(
    page === "signup" ? "/login.html?registered" : "/pages/dashboard.html",
  );
});
