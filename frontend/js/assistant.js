import { $, icon, submit, api } from "./common.js";
export function assistant() {
  document.body.insertAdjacentHTML(
    "beforeend",
    '<button class="robot" aria-label="Open CyberShield Assistant" aria-expanded="false"><span class="face"><i></i><i></i></span></button><section class="chat" hidden aria-label="CyberShield Assistant"><div class="row"><strong>CyberShield Assistant</strong><button id="minchat" aria-label="Minimize chat">−</button><button id="closechat" aria-label="Close chat">×</button></div><small id="chatmode">Local safety guide</small><div class="chatlog" aria-live="polite"></div><form><input aria-label="Message" name="message" placeholder="Ask about a check…" maxlength="500" required><button aria-label="Send">' +
      icon("send") +
      "</button><output></output></form></section>",
  );
  const robot = $(".robot"),
    chat = $(".chat"),
    log = $(".chatlog");
  function add(text) {
    const p = document.createElement("p");
    p.textContent = text;
    log.append(p);
    log.scrollTop = log.scrollHeight;
  }
  function open(on) {
    chat.hidden = !on;
    robot.setAttribute("aria-expanded", String(on));
    if (on) {
      if (!log.children.length)
        add(
          "Hi! I’m your CyberShield Assistant. Ask me about a suspicious email, a scan score or finding your reports.",
        );
      chat.querySelector("input").focus();
    } else robot.focus();
  }
  robot.onclick = () => open(chat.hidden);
  $("#minchat").onclick = () => open(false);
  $("#closechat").onclick = () => {
    log.replaceChildren();
    open(false);
  };
  if (
    matchMedia("(pointer:fine) and (prefers-reduced-motion:no-preference)")
      .matches
  )
    window.addEventListener("pointermove", (e) => {
      const r = robot.getBoundingClientRect(),
        dx = e.clientX - r.x - r.width / 2,
        dy = e.clientY - r.y - r.height / 2,
        angle = Math.atan2(dy, dx);
      robot.style.setProperty("--x", Math.cos(angle) * 3 + "px");
      robot.style.setProperty("--y", Math.sin(angle) * 2 + "px");
      robot.style.setProperty("--turn", Math.cos(angle) * 5 + "deg");
    });
  const consent = document.createElement("label");
  consent.className = "check";
  consent.innerHTML =
    '<input type="checkbox"> Send my question to AI if configured';
  chat.querySelector("form").before(consent);
  submit(chat.querySelector("form"), async (data, form) => {
    add("You · " + data.message);
    form.reset();
    data.useAI = consent.querySelector("input").checked;
    const r = await api("assistant", "POST", data);
    $("#chatmode").textContent = r.mode;
    add(r.answer);
  });
}
