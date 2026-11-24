import { $, icon, api } from "./common.js";

function appendRichText(container, text) {
  const pattern = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s<]+)/gi;
  let offset = 0;
  for (const match of text.matchAll(pattern)) {
    const rawUrl = match[2] || match[3];
    const url = rawUrl.replace(/[),.!?]+$/, "");
    const end = match.index + match[0].length;
    container.append(document.createTextNode(text.slice(offset, match.index)));
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
        throw Error("Unsupported link protocol");
      const link = document.createElement("a");
      link.href = parsed.href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = match[1] || url;
      container.append(link);
      container.append(document.createTextNode(text.slice(end - (rawUrl.length - url.length), end)));
    } catch {
      container.append(document.createTextNode(match[0]));
    }
    offset = end;
  }
  container.append(document.createTextNode(text.slice(offset)));
}

function formatReply(container, text) {
  let list = null;
  for (const line of String(text).replace(/\r\n?/g, "\n").split("\n")) {
    const item = line.match(/^\s*(?:[-*]\s+|\d+[.)]\s+)(.*)$/);
    if (!line.trim()) {
      list = null;
      continue;
    }
    if (item) {
      if (!list) {
        list = document.createElement(/^\s*\d+[.)]/.test(line) ? "ol" : "ul");
        container.append(list);
      }
      const li = document.createElement("li");
      appendRichText(li, item[1]);
      list.append(li);
    } else {
      list = null;
      const paragraph = document.createElement("p");
      appendRichText(paragraph, line);
      container.append(paragraph);
    }
  }
}

export function assistant() {
  document.body.insertAdjacentHTML(
    "beforeend",
    '<button class="robot" aria-label="Open CyberShield Assistant" aria-expanded="false"><span class="face"><i></i><i></i></span></button><section class="chat" hidden role="dialog" aria-modal="false" aria-labelledby="chat-title"><div class="chat-header"><strong id="chat-title">CyberShield Assistant</strong><button id="minchat" aria-label="Minimize chat">−</button><button id="closechat" aria-label="Close chat">×</button></div><small id="chatmode">Local safety guide</small><div class="chatlog" role="log" aria-live="polite" aria-relevant="additions"></div><form><label for="chat-message">Message</label><textarea id="chat-message" name="message" placeholder="Ask about a check…" maxlength="500" rows="2" required></textarea><button class="chat-send" aria-label="Send message">' +
      icon("send") +
      "<span>Send</span></button><output></output></form></section>",
  );
  const robot = $(".robot");
  const chat = $(".chat");
  const log = $(".chatlog");
  const form = chat.querySelector("form");
  const composer = $("#chat-message");
  const send = chat.querySelector(".chat-send");
  let retryText = "";

  function addMessage(role, text) {
    const message = document.createElement("article");
    message.className = "chat-message " + role;
    const label = document.createElement("strong");
    label.className = "chat-message-label";
    label.textContent = role === "user" ? "You" : "Assistant";
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";
    formatReply(bubble, text);
    message.append(label, bubble);
    log.append(message);
    log.scrollTop = log.scrollHeight;
    return message;
  }

  function open(on) {
    chat.hidden = !on;
    robot.setAttribute("aria-expanded", String(on));
    if (on) {
      if (!log.children.length)
        addMessage(
          "assistant",
          "Hi! I’m your CyberShield Assistant. Ask me about a suspicious email, a scan score or finding your reports.",
        );
      composer.focus();
    } else robot.focus();
  }

  async function sendMessage(text, retry = false) {
    if (!text.trim() || send.disabled) return;
    if (!retry) {
      addMessage("user", text);
      retryText = text;
      form.reset();
    }
    send.disabled = true;
    const status = document.createElement("p");
    status.className = "chat-status";
    status.setAttribute("role", "status");
    status.textContent = "Responding…";
    log.append(status);
    log.scrollTop = log.scrollHeight;
    try {
      const consent = chat.querySelector(".chat-consent input");
      const result = await api("assistant", "POST", {
        message: text,
        useAI: consent.checked,
      });
      status.remove();
      $("#chatmode").textContent = result.mode;
      addMessage("assistant", result.answer);
      retryText = "";
    } catch (error) {
      status.remove();
      const failed = addMessage(
        "assistant",
        "I couldn’t get a reply. Check your connection and try again.",
      );
      const retry = document.createElement("button");
      retry.type = "button";
      retry.className = "chat-retry";
      retry.textContent = "Retry";
      retry.onclick = () => {
        failed.remove();
        sendMessage(retryText, true);
      };
      failed.querySelector(".chat-bubble").append(retry);
      form.querySelector("output").textContent = error.message;
    } finally {
      send.disabled = false;
      composer.focus();
    }
  }

  robot.onclick = () => open(chat.hidden);
  chat.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !chat.hidden) {
      event.preventDefault();
      open(false);
    }
  });
  $("#minchat").onclick = () => open(false);
  $("#closechat").onclick = () => {
    log.replaceChildren();
    retryText = "";
    open(false);
  };
  composer.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      form.requestSubmit();
    }
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    form.querySelector("output").textContent = "";
    sendMessage(composer.value);
  });

  const consent = document.createElement("label");
  consent.className = "check chat-consent";
  consent.innerHTML =
    '<input type="checkbox"> Send my question to AI if configured';
  chat.insertBefore(consent, form);

  if (window.visualViewport) {
    const updateViewport = () => {
      chat.style.setProperty(
        "--chat-vh",
        window.visualViewport.height + "px",
      );
      chat.style.setProperty(
        "--chat-vv-bottom",
        Math.max(
          0,
          window.innerHeight -
            window.visualViewport.height -
            window.visualViewport.offsetTop,
        ) + "px",
      );
    };
    window.visualViewport.addEventListener("resize", updateViewport);
    window.visualViewport.addEventListener("scroll", updateViewport);
    updateViewport();
  }
  if (
    matchMedia("(pointer:fine) and (prefers-reduced-motion:no-preference)")
      .matches
  )
    window.addEventListener("pointermove", (event) => {
      const rect = robot.getBoundingClientRect();
      const angle = Math.atan2(
        event.clientY - rect.y - rect.height / 2,
        event.clientX - rect.x - rect.width / 2,
      );
      robot.style.setProperty("--x", Math.cos(angle) * 3 + "px");
      robot.style.setProperty("--y", Math.sin(angle) * 2 + "px");
      robot.style.setProperty("--turn", Math.cos(angle) * 5 + "deg");
    });
}
