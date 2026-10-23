// Ashy Pass inline suggestions menu. Runs as an extension page framed in the
// web page (the page cannot read it). It gets an opening token from the
// content script that created it and uses it to ask the background for the
// suggestions of the tab, and to fill one of them into the field's frame.

import { FaviconBatcher, TOKEN_RE, avatarFor, faviconHost } from "../lib/helpers.js";
import { applyIcons } from "../lib/icons.js";

const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

let token = null;
let loading = false;

function t(key, substitutions) {
  return api.i18n.getMessage(key, substitutions) || key;
}

function applyI18n() {
  const locale = api.i18n.getMessage("@@ui_locale");
  if (locale) document.documentElement.lang = locale.replace("_", "-");
  document.documentElement.dir = api.i18n.getMessage("@@bidi_dir") || "ltr";
  for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of document.querySelectorAll("[data-i18n-aria-label]")) el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
}

async function send(type, data = {}) {
  try {
    const reply = await api.runtime.sendMessage({ ...data, type, token });
    return reply && typeof reply === "object" ? reply : { ok: false, code: "internal" };
  } catch {
    return { ok: false, code: "internal" };
  }
}

/** Messages to the content script of the page (no data, only UI events). */
function toParent(type, extra = {}) {
  window.parent.postMessage({ ...extra, source: "ashypass-menu", type }, "*");
}

// ── States ──────────────────────────────────────────────────────────────────

function show(id) {
  $("state-loading").hidden = id !== "state-loading";
  $("state-message").hidden = id !== "state-message";
  $("menu-list").hidden = id !== "menu-list";
}

function showMessage(text, action = null) {
  $("message-text").textContent = text;
  const button = $("message-action");
  button.hidden = action === null;
  if (action) {
    button.textContent = action.label;
    button.onclick = action.run;
  }
  show("state-message");
}

const STATE_TEXT = {
  not_installed: "notInstalledTitle",
  disabled: "disabledTitle",
  no_vault: "noVaultTitle",
};

function errorText(reply) {
  if (reply.code === "bad_token") return t("inlineExpired");
  if (reply.code === "no_match") return t("errorNoMatch");
  if (reply.code === "cannot_access") return t("errorCannotAccess");
  if (reply.code === "timeout") return t("errorTimeout");
  if (reply.code === "disconnected") return t("errorDisconnected");
  return t("errorTitle");
}

async function load() {
  if (!token || loading) return;
  loading = true;
  show("state-loading");
  const reply = await send("inlineMenuState");
  loading = false;
  if (!reply.ok) {
    if (reply.code === "bad_token") token = null; // a forged or stale token: wait for a real one
    $("menu-footer").hidden = true;
    showMessage(errorText(reply));
    return;
  }
  $("menu-host").textContent = reply.host || "";
  if (reply.state === "locked") {
    $("menu-footer").hidden = true;
    showMessage(t("inlineLocked"), { label: t("unlockButton"), run: () => openPopup(null) });
    return;
  }
  if (reply.state !== "unlocked") {
    $("menu-footer").hidden = true;
    showMessage(t(STATE_TEXT[reply.state] ?? "errorTitle"));
    return;
  }
  $("menu-footer").hidden = false;
  if (reply.entries.length === 0) {
    showMessage(t("inlineNoLogins"));
    return;
  }
  renderList(reply.entries);
}

// ── List ────────────────────────────────────────────────────────────────────

const favicons = new FaviconBatcher(async (hosts) => {
  const reply = await send("favicons", { hosts });
  return reply.ok ? reply.icons : {};
});

function faviconFor(entry) {
  const el = document.createElement("span");
  el.className = "favicon";
  el.setAttribute("aria-hidden", "true");
  const { letter, color } = avatarFor(entry.title || entry.url);
  const fallback = document.createElement("span");
  fallback.className = "avatar";
  fallback.textContent = letter;
  fallback.style.backgroundColor = color;
  el.append(fallback);
  const host = faviconHost(entry.url);
  if (host) {
    favicons.get(host).then((url) => {
      if (!url) return;
      const img = document.createElement("img");
      img.alt = "";
      img.src = url;
      img.addEventListener("load", () => el.replaceChildren(img), { once: true });
    });
  }
  return el;
}

function renderList(entries) {
  const items = entries.map((entry) => {
    const title = entry.title || t("untitled");
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.className = "item";
    b.setAttribute("aria-label", t("fillLabel", [title]));
    const text = document.createElement("span");
    text.className = "item-text";
    const name = document.createElement("span");
    name.className = "item-title";
    name.textContent = title;
    const user = document.createElement("span");
    user.className = "item-user";
    user.textContent = entry.username || t("noUsername");
    text.append(name, user);
    b.append(faviconFor(entry), text);
    b.addEventListener("click", () => fill(entry, b));
    li.append(b);
    return li;
  });
  $("menu-list").replaceChildren(...items);
  show("menu-list");
}

async function fill(entry, el) {
  if (!token) return;
  for (const b of document.querySelectorAll(".item")) b.disabled = true;
  const reply = await send("inlineFill", { id: entry.id });
  token = null; // single use
  if (reply.ok && reply.filled > 0) {
    toParent("filled");
    return;
  }
  el.disabled = false;
  $("menu-footer").hidden = true;
  showMessage(reply.ok ? t("noLoginForm") : errorText(reply));
}

// ── Popup ───────────────────────────────────────────────────────────────────

function openPopup(view) {
  if (!token) return;
  // Record the wanted view first (messages keep their order), then open the
  // popup straight from the click: Firefox only allows it with a user gesture.
  send("inlineOpenPopup", { view, open: false });
  let attempt;
  try {
    attempt = Promise.resolve(api.action.openPopup());
  } catch (err) {
    attempt = Promise.reject(err);
  }
  attempt
    .then(() => toParent("close"))
    .catch(async () => {
      const reply = await send("inlineOpenPopup", { view, open: true });
      if (reply.ok && reply.opened) toParent("close");
      else showMessage(t("inlineClickIcon"));
    });
}

// ── Keyboard ────────────────────────────────────────────────────────────────

function focusables() {
  return [...document.querySelectorAll(".item:not(:disabled), #message-action:not([hidden]), #menu-add")].filter(
    (el) => el.offsetParent !== null,
  );
}

function onKey(event) {
  const items = focusables();
  const index = items.indexOf(document.activeElement);
  switch (event.key) {
    case "ArrowDown":
      event.preventDefault();
      items[Math.min(index + 1, items.length - 1)]?.focus();
      break;
    case "ArrowUp":
      event.preventDefault();
      if (index <= 0) toParent("focusField");
      else items[index - 1].focus();
      break;
    case "Home":
      event.preventDefault();
      items[0]?.focus();
      break;
    case "End":
      event.preventDefault();
      items[items.length - 1]?.focus();
      break;
    case "Escape":
      event.preventDefault();
      toParent("close", { suppress: true });
      break;
    default:
      break;
  }
}

// ── Start ───────────────────────────────────────────────────────────────────

window.addEventListener("message", (ev) => {
  if (ev.source !== window.parent) return;
  const data = ev.data;
  if (!data || typeof data !== "object" || data.source !== "ashypass-content") return;
  if (data.type === "init" && token === null && typeof data.token === "string" && TOKEN_RE.test(data.token)) {
    token = data.token;
    load();
  } else if (data.type === "focusList") {
    focusables()[0]?.focus();
  }
});

applyI18n();
applyIcons();
document.addEventListener("keydown", onKey);
$("menu-add").addEventListener("click", () => openPopup("add"));
new ResizeObserver(() => toParent("resize", { height: document.querySelector(".menu").scrollHeight })).observe(
  document.querySelector(".menu"),
);
toParent("ready");
