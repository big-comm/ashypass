// Ashy Pass popup. Talks only to the background script; never stores secrets.

import { SEARCH_DEBOUNCE_MS, debounce, maskSecret } from "../lib/helpers.js";

const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

const TOAST_MS = 2500;
const VIEWS = ["view-loading", "view-message", "view-locked", "view-unlocked"];

const state = {
  tabId: null,
  host: "",
  fillable: false,
  matches: [],
  matchIds: new Set(),
  searchSeq: 0,
  generated: "",
  revealed: false,
};

function t(key, substitutions) {
  return api.i18n.getMessage(key, substitutions) || key;
}

function applyI18n() {
  const locale = api.i18n.getMessage("@@ui_locale");
  if (locale) document.documentElement.lang = locale.replace("_", "-");
  document.documentElement.dir = api.i18n.getMessage("@@bidi_dir") || "ltr";
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of document.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
}

async function send(type, data = {}) {
  try {
    const reply = await api.runtime.sendMessage({ ...data, type });
    return reply && typeof reply === "object" ? reply : { ok: false, code: "internal", error: "" };
  } catch (err) {
    return { ok: false, code: "internal", error: String(err?.message ?? err) };
  }
}

// ── Feedback ────────────────────────────────────────────────────────────────

let toastTimer = null;
function toast(message, { error = false } = {}) {
  const el = $("status");
  el.textContent = message;
  el.classList.toggle("error-toast", error);
  el.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove("visible");
    el.textContent = "";
  }, TOAST_MS);
}

function errorText(reply) {
  switch (reply.code) {
    case "timeout":
      return t("errorTimeout");
    case "disconnected":
      return t("errorDisconnected");
    case "no_match":
      return t("errorNoMatch");
    case "not_found":
      return t("errorNotFound");
    case "no_totp":
      return t("errorNoTotp");
    case "not_web_page":
      return t("notAWebPage");
    case "cannot_access":
      return t("errorCannotAccess");
    case "bad_password":
      return t("badPassword");
    case "rate_limited":
      return t("rateLimited");
    default:
      return reply.error ? t("errorDetail", [reply.error]) : t("errorTitle");
  }
}

/** Shared error handling for actions; returns true when it changed the view. */
function handleFailure(reply) {
  if (reply.code === "locked") {
    showLocked();
    return true;
  }
  if (["not_installed", "disabled", "no_vault"].includes(reply.code)) {
    showState(reply.code);
    return true;
  }
  toast(errorText(reply), { error: true });
  return false;
}

// ── Views ───────────────────────────────────────────────────────────────────

function showView(id) {
  for (const view of VIEWS) $(view).hidden = view !== id;
}

function showMessage(title, body) {
  $("message-title").textContent = title;
  $("message-body").textContent = body;
  showView("view-message");
  $("retry").focus();
}

function showState(name, reply) {
  setHost("");
  switch (name) {
    case "not_installed":
      showMessage(t("notInstalledTitle"), t("notInstalledBody"));
      break;
    case "disabled":
      showMessage(t("disabledTitle"), t("disabledBody"));
      break;
    case "no_vault":
      showMessage(t("noVaultTitle"), t("noVaultBody"));
      break;
    case "locked":
      showLocked();
      break;
    case "unlocked":
      showUnlocked();
      break;
    default:
      showMessage(t("errorTitle"), reply ? errorText(reply) : "");
  }
}

function setHost(host) {
  const el = $("site-host");
  el.textContent = host;
  el.hidden = host === "";
}

async function refresh() {
  showView("view-loading");
  const reply = await send("status");
  if (reply.ok) showState(reply.state);
  else showState("error", reply);
}

function showLocked() {
  setHost("");
  resetGenerated();
  $("unlock-error").textContent = "";
  showView("view-locked");
  $("master-password").focus();
}

async function onUnlock(event) {
  event.preventDefault();
  const input = $("master-password");
  const button = $("unlock");
  let password = input.value;
  input.value = "";
  if (password === "") {
    input.focus();
    return;
  }
  button.disabled = true;
  button.textContent = t("unlocking");
  $("unlock-error").textContent = "";
  const reply = await send("unlock", { password });
  password = "";
  button.disabled = false;
  button.textContent = t("unlockButton");
  if (reply.ok) {
    showUnlocked();
    return;
  }
  if (["not_installed", "disabled", "no_vault"].includes(reply.code)) {
    showState(reply.code);
    return;
  }
  $("unlock-error").textContent = errorText(reply);
  input.focus();
}

async function showUnlocked() {
  showView("view-unlocked");
  $("search").value = "";
  const reply = await send("match", { tabId: state.tabId });
  if (!reply.ok) {
    if (handleFailure(reply)) return;
    state.matches = [];
    state.fillable = false;
  } else {
    state.matches = reply.entries;
    state.fillable = reply.fillable === true;
    state.host = reply.host || "";
  }
  state.matchIds = new Set(state.matches.map((e) => e.id));
  setHost(state.host);
  renderMatches();
  $("search").focus();
}

// ── Entry list ──────────────────────────────────────────────────────────────

function renderMatches() {
  $("list-heading").textContent = t("siteEntriesHeading");
  const empty = state.fillable ? t("noEntriesForSite") : t("notAWebPage");
  renderList(state.matches, empty);
}

function renderList(entries, emptyText) {
  const list = $("entry-list");
  list.replaceChildren(...entries.map(entryRow));
  list.hidden = entries.length === 0;
  $("list-empty").textContent = emptyText;
  $("list-empty").hidden = entries.length !== 0;
}

function button(label, ariaLabel, className, onClick) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  b.textContent = label;
  b.setAttribute("aria-label", ariaLabel);
  b.addEventListener("click", onClick);
  return b;
}

function entryRow(entry) {
  const title = entry.title || t("untitled");
  const li = document.createElement("li");
  li.className = "row";

  const text = document.createElement("div");
  text.className = "row-text";
  const name = document.createElement("span");
  name.className = "row-title";
  name.textContent = title;
  const user = document.createElement("span");
  user.className = "row-subtitle";
  user.textContent = entry.username || t("noUsername");
  text.append(name, user);

  const actions = document.createElement("div");
  actions.className = "row-actions";
  // Fill only for entries the host matched to this page.
  if (state.fillable && state.matchIds.has(entry.id)) {
    actions.append(button(t("fillButton"), t("fillLabel", [title]), "pill suggested small", (ev) => onFill(entry, ev.currentTarget)));
  }
  if (entry.username) {
    actions.append(button(t("copyUsernameButton"), t("copyUsernameLabel", [title]), "pill small", (ev) => onCopy(entry, "username", ev.currentTarget)));
  }
  actions.append(button(t("copyPasswordButton"), t("copyPasswordLabel", [title]), "pill small", (ev) => onCopy(entry, "password", ev.currentTarget)));
  if (entry.has_totp) {
    actions.append(button(t("copyCodeButton"), t("copyCodeLabel", [title]), "pill small", (ev) => onCopy(entry, "totp", ev.currentTarget)));
  }

  li.append(text, actions);
  return li;
}

async function runSearch(query) {
  const seq = ++state.searchSeq;
  if (query === "") {
    renderMatches();
    return;
  }
  const reply = await send("search", { query });
  if (seq !== state.searchSeq) return; // a newer search is running
  if (!reply.ok) {
    handleFailure(reply);
    return;
  }
  $("list-heading").textContent = t("searchResultsHeading");
  renderList(reply.entries, t("noSearchResults"));
}

const debouncedSearch = debounce((q) => runSearch(q), SEARCH_DEBOUNCE_MS);

// ── Actions ─────────────────────────────────────────────────────────────────

async function withBusy(el, fn) {
  if (el) el.disabled = true;
  try {
    return await fn();
  } finally {
    if (el) el.disabled = false;
  }
}

function onFill(entry, el) {
  return withBusy(el, async () => {
    const reply = await send("fill", { tabId: state.tabId, id: entry.id });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    if (reply.filled > 0) toast(t("filled"));
    else toast(t("noLoginForm"), { error: true });
  });
}

async function writeClipboard(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

const COPIED = { username: "usernameCopied", password: "passwordCopied", totp: "codeCopied" };

function onCopy(entry, field, el) {
  return withBusy(el, async () => {
    const reply = await send("copy", { id: entry.id, field });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    const ok = await writeClipboard(reply.value);
    reply.value = "";
    toast(ok ? t(COPIED[field]) : t("copyFailed"), { error: !ok });
  });
}

function renderGenerated() {
  const value = $("generated-value");
  const reveal = $("reveal");
  value.textContent = state.revealed ? state.generated : maskSecret(state.generated);
  reveal.textContent = state.revealed ? t("hidePassword") : t("revealPassword");
  reveal.setAttribute("aria-pressed", String(state.revealed));
}

function resetGenerated() {
  state.generated = "";
  state.revealed = false;
  $("generated").hidden = true;
  $("generated-value").textContent = "";
}

function onGenerate() {
  return withBusy($("generate"), async () => {
    const reply = await send("generate", { kind: "password" });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    state.generated = reply.value;
    reply.value = "";
    state.revealed = false;
    $("generated").hidden = false;
    renderGenerated();
    const ok = await writeClipboard(state.generated);
    toast(ok ? t("generatedCopied") : t("copyFailed"), { error: !ok });
  });
}

function onReveal() {
  state.revealed = !state.revealed;
  renderGenerated();
}

function onLock() {
  return withBusy($("lock"), async () => {
    const reply = await send("lock");
    if (!reply.ok && handleFailure(reply)) return;
    showLocked();
    toast(t("vaultLocked"));
  });
}

// ── Start ───────────────────────────────────────────────────────────────────

async function init() {
  applyI18n();
  $("unlock-form").addEventListener("submit", onUnlock);
  $("retry").addEventListener("click", refresh);
  $("generate").addEventListener("click", onGenerate);
  $("reveal").addEventListener("click", onReveal);
  $("lock").addEventListener("click", onLock);
  $("search").addEventListener("input", (ev) => debouncedSearch(ev.target.value.trim()));
  $("search").addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && ev.target.value !== "") {
      ev.preventDefault();
      ev.target.value = "";
      debouncedSearch.cancel();
      runSearch("");
    }
  });
  window.addEventListener("pagehide", resetGenerated);

  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    state.tabId = tab?.id ?? null;
  } catch {
    state.tabId = null;
  }
  await refresh();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
  init();
}
