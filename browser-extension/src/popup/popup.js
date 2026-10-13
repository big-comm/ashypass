// Ashy Pass popup. Talks only to the background script; never stores secrets.
// Only the generator options and "hint dismissed" go to storage.local.

import {
  FaviconBatcher,
  GENERATOR_RANGES,
  INLINE_MATCHES,
  LIST_CHUNK_SIZE,
  NO_FOLDER,
  SEARCH_DEBOUNCE_MS,
  avatarFor,
  debounce,
  faviconHost,
  filterEntries,
  hasActiveFilter,
  normalizeGeneratorOptions,
  openableUrl,
  totpFraction,
} from "../lib/helpers.js";
import { applyIcons, icon } from "../lib/icons.js";

const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

const TOAST_MS = 2500;
const STORAGE_GENERATOR = "generatorOptions";
const STORAGE_HINT = "inlineHintDismissed";
const HELP_URL = "https://github.com/big-comm/ashypass";
const PRIVACY_URL = "https://github.com/big-comm/ashypass/blob/main/browser-extension/README.md#security-model";
const VIEWS = [
  "view-loading",
  "view-message",
  "view-locked",
  "view-vault",
  "view-details",
  "view-add",
  "view-generator",
  "view-settings",
];
const RING_CIRCUMFERENCE = 2 * Math.PI * 10;
const MASK = "••••••••••••";

const state = {
  tabId: null,
  host: "",
  origin: "",
  fillable: false,
  matches: [],
  matchIds: new Set(),
  all: [],
  folders: [],
  query: "",
  searchSeq: 0,
  searchResults: [],
  filter: { folder: "", type: "all" },
  pinAvailable: false,
  unlockMode: "password",
  tab: "vault",
  view: "view-loading",
  vaultScroll: 0,
  vaultLoaded: false,
  vaultDirty: false,
  inlineEnabled: false,
  hintDismissed: true,
  allList: [],
  allRendered: 0,
  detail: null,
  gen: { options: normalizeGeneratorOptions(null), value: "", seq: 0 },
};

// ── i18n ────────────────────────────────────────────────────────────────────

function t(key, substitutions) {
  return api.i18n.getMessage(key, substitutions) || key;
}

function applyI18n(root = document) {
  const locale = api.i18n.getMessage("@@ui_locale");
  if (locale) document.documentElement.lang = locale.replace("_", "-");
  document.documentElement.dir = api.i18n.getMessage("@@bidi_dir") || "ltr";
  for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) el.placeholder = t(el.dataset.i18nPlaceholder);
  for (const el of root.querySelectorAll("[data-i18n-aria-label]")) el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
  for (const el of root.querySelectorAll("[data-i18n-title]")) setLabel(el, t(el.dataset.i18nTitle));
}

/** Tooltip and accessible name of an icon button. */
function setLabel(el, text) {
  el.title = text;
  el.setAttribute("aria-label", text);
}

// ── Messaging ───────────────────────────────────────────────────────────────

async function send(type, data = {}) {
  try {
    const reply = await api.runtime.sendMessage({ ...data, type });
    return reply && typeof reply === "object" ? reply : { ok: false, code: "internal", error: "" };
  } catch (err) {
    return { ok: false, code: "internal", error: String(err?.message ?? err) };
  }
}

async function storageGet(key) {
  try {
    const items = await api.storage.local.get(key);
    return items?.[key];
  } catch {
    return undefined;
  }
}

async function storageSet(key, value) {
  try {
    await api.storage.local.set({ [key]: value });
  } catch {
    // Not critical: the option is just not remembered.
  }
}

// ── Feedback ────────────────────────────────────────────────────────────────

let toastTimer = null;
function toast(message, { error = false } = {}) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("error-toast", error);
  el.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove("visible");
    el.textContent = "";
  }, TOAST_MS);
}

const ERROR_MESSAGES = {
  timeout: "errorTimeout",
  disconnected: "errorDisconnected",
  no_match: "errorNoMatch",
  not_found: "errorNotFound",
  no_totp: "errorNoTotp",
  not_web_page: "notAWebPage",
  cannot_access: "errorCannotAccess",
  bad_password: "badPassword",
  rate_limited: "rateLimited",
  pin_unavailable: "pinUnavailableNote",
  pin_disabled: "pinDisabledNote",
  permission_denied: "permissionDenied",
  invalid: "errorInvalid",
};

function errorText(reply) {
  if (reply.code === "bad_pin") {
    return Number.isInteger(reply.attempts_left) ? t("badPinAttempts", [String(reply.attempts_left)]) : t("badPin");
  }
  if (Object.hasOwn(ERROR_MESSAGES, reply.code)) return t(ERROR_MESSAGES[reply.code]);
  return reply.error ? t("errorDetail", [reply.error]) : t("errorTitle");
}

/** Shared error handling for actions; returns true when it changed the view. */
function handleFailure(reply) {
  if (reply.code === "locked") {
    refresh();
    return true;
  }
  if (["not_installed", "disabled", "no_vault"].includes(reply.code)) {
    showState(reply.code);
    return true;
  }
  toast(errorText(reply), { error: true });
  return false;
}

async function withBusy(el, fn) {
  if (el) el.disabled = true;
  try {
    return await fn();
  } finally {
    if (el) el.disabled = false;
  }
}

async function writeClipboard(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

function openTab(url) {
  const safe = openableUrl(url);
  if (safe === "") return;
  api.tabs.create({ url: safe }).catch(() => {});
}

// ── Views and header ────────────────────────────────────────────────────────

function showView(id) {
  closeRowMenu();
  if (state.view === "view-vault" && id !== "view-vault") state.vaultScroll = $("main").scrollTop;
  if (state.view === "view-details" && id !== "view-details") closeDetails();
  if (state.view === "view-add" && id !== "view-add") resetAddForm();
  state.view = id;
  for (const view of VIEWS) $(view).hidden = view !== id;
  $("main").scrollTop = id === "view-vault" ? state.vaultScroll : 0;
}

function setHeader({ title = t("extName"), back = false, add = false, lock = false } = {}) {
  $("header-title").textContent = title;
  $("back").hidden = !back;
  $("header-logo").hidden = back;
  $("add").hidden = !add;
  $("lock").hidden = !lock;
}

function setTabbar(visible) {
  $("tabbar").hidden = !visible;
  for (const button of $("tabbar").querySelectorAll("[role=tab]")) {
    const selected = button.dataset.tab === state.tab;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  }
}

function showMessage(title, body, { openApp = false } = {}) {
  setHeader();
  setTabbar(false);
  $("message-title").textContent = title;
  $("message-body").textContent = body;
  $("message-open-app").hidden = !openApp;
  showView("view-message");
  (openApp ? $("message-open-app") : $("retry")).focus();
}

function showState(name, reply) {
  switch (name) {
    case "not_installed":
      showMessage(t("notInstalledTitle"), t("notInstalledBody"));
      break;
    case "disabled":
      showMessage(t("disabledTitle"), t("disabledBody"), { openApp: true });
      break;
    case "no_vault":
      showMessage(t("noVaultTitle"), t("noVaultBody"), { openApp: true });
      break;
    case "locked":
      showLocked();
      break;
    case "unlocked":
      enterUnlocked();
      break;
    default:
      showMessage(t("errorTitle"), reply ? errorText(reply) : "");
  }
}

async function refresh() {
  setHeader();
  setTabbar(false);
  showView("view-loading");
  const reply = await send("status");
  if (!reply.ok) {
    showState("error", reply);
    return;
  }
  state.pinAvailable = reply.pinAvailable === true;
  showState(reply.state);
}

// ── Locked ──────────────────────────────────────────────────────────────────

function renderUnlockMode() {
  const pin = state.unlockMode === "pin";
  const input = $("unlock-input");
  $("unlock-label").textContent = pin ? t("pinLabel") : t("masterPasswordLabel");
  $("unlock-submit").textContent = pin ? t("unlockWithPinButton") : t("unlockButton");
  if (pin) {
    input.setAttribute("inputmode", "numeric");
    input.autocomplete = "off";
  } else {
    input.removeAttribute("inputmode");
    input.autocomplete = "current-password";
  }
  const sw = $("unlock-switch");
  sw.hidden = !state.pinAvailable;
  sw.textContent = pin ? t("useMasterPassword") : t("usePin");
}

function showLocked({ note = "" } = {}) {
  setHeader();
  setTabbar(false);
  resetGenerated();
  state.vaultLoaded = false;
  state.unlockMode = state.pinAvailable ? "pin" : "password";
  renderUnlockMode();
  $("unlock-error").textContent = "";
  $("unlock-note").textContent = note;
  $("unlock-input").value = "";
  showView("view-locked");
  $("unlock-input").focus();
}

function onUnlockSwitch() {
  state.unlockMode = state.unlockMode === "pin" ? "password" : "pin";
  $("unlock-error").textContent = "";
  $("unlock-note").textContent = "";
  $("unlock-input").value = "";
  renderUnlockMode();
  $("unlock-input").focus();
}

async function onUnlock(event) {
  event.preventDefault();
  const input = $("unlock-input");
  const submit = $("unlock-submit");
  let secret = input.value;
  input.value = "";
  if (secret === "") {
    input.focus();
    return;
  }
  const pin = state.unlockMode === "pin";
  submit.disabled = true;
  submit.textContent = t("unlocking");
  $("unlock-error").textContent = "";
  const reply = pin ? await send("unlockPin", { pin: secret }) : await send("unlock", { password: secret });
  secret = "";
  submit.disabled = false;
  renderUnlockMode();
  if (reply.ok) {
    $("unlock-note").textContent = "";
    enterUnlocked();
    return;
  }
  if (["not_installed", "disabled", "no_vault"].includes(reply.code)) {
    showState(reply.code);
    return;
  }
  if (reply.code === "pin_disabled" || reply.code === "pin_unavailable") {
    state.pinAvailable = false;
    state.unlockMode = "password";
    renderUnlockMode();
    $("unlock-note").textContent = errorText(reply);
  } else {
    $("unlock-error").textContent = errorText(reply);
  }
  input.focus();
}

// ── Unlocked: tabs ──────────────────────────────────────────────────────────

async function enterUnlocked() {
  state.tab = "vault";
  setTabbar(true);
  const [pending] = await Promise.all([send("takePendingView", { tabId: state.tabId }), loadVault()]);
  if (state.view === "view-locked" || state.view === "view-message") return;
  if (pending.ok && pending.view === "add") openAdd();
}

function showTab(name) {
  state.tab = name;
  setTabbar(true);
  if (name === "generator") showGenerator();
  else if (name === "settings") showSettings();
  else showVault();
}

function onTabKey(event) {
  const tabs = [...$("tabbar").querySelectorAll("[role=tab]")];
  const index = tabs.indexOf(event.target.closest("[role=tab]"));
  if (index < 0) return;
  let next = -1;
  if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
  else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = tabs.length - 1;
  if (next < 0) return;
  event.preventDefault();
  tabs[next].focus();
  showTab(tabs[next].dataset.tab);
}

// ── Vault ───────────────────────────────────────────────────────────────────

async function loadVault() {
  setHeader({ title: t("tabVault"), add: true, lock: true });
  showView("view-vault");
  const [match, list, folders, inline, hintDismissed] = await Promise.all([
    send("match", { tabId: state.tabId }),
    send("list"),
    send("folders"),
    send("inlineState"),
    storageGet(STORAGE_HINT),
  ]);
  for (const reply of [match, list]) {
    if (!reply.ok && handleFailure(reply)) return;
  }
  state.matches = match.ok ? match.entries : [];
  state.fillable = match.ok && match.fillable === true;
  state.host = match.ok ? match.host || "" : "";
  state.origin = match.ok ? match.origin || "" : "";
  state.matchIds = new Set(state.matches.map((e) => e.id));
  state.all = list.ok ? list.entries : [];
  state.folders = folders.ok ? folders.folders : [];
  state.inlineEnabled = inline.ok && inline.enabled === true;
  state.hintDismissed = hintDismissed === true;
  state.vaultLoaded = true;
  renderFolderFilter();
  renderVault();
  if (state.view === "view-vault") $("search").focus();
}

function showVault() {
  setHeader({ title: t("tabVault"), add: true, lock: true });
  if (!state.vaultLoaded) {
    loadVault();
    return;
  }
  showView("view-vault");
  if (state.vaultDirty) renderVault({ keepScroll: true });
}

function option(value, text) {
  const o = document.createElement("option");
  o.value = value;
  o.textContent = text;
  return o;
}

function renderFolderFilter() {
  const select = $("filter-folder");
  const options = [option("", t("filterAllFolders")), option(NO_FOLDER, t("noFolder"))];
  for (const name of state.folders) options.push(option(name, name));
  select.replaceChildren(...options);
  const known = state.filter.folder === "" || state.filter.folder === NO_FOLDER || state.folders.includes(state.filter.folder);
  if (!known) state.filter.folder = "";
  select.value = state.filter.folder;
  $("filter-type").value = state.filter.type;
}

function renderVault({ keepScroll = false } = {}) {
  state.vaultDirty = false;
  const scroll = $("main").scrollTop;
  const filtering = state.query !== "" || hasActiveFilter(state.filter);

  $("inline-hint").hidden = state.inlineEnabled || state.hintDismissed || filtering;

  $("sec-suggestions").hidden = filtering;
  $("sec-favorites").hidden = true;
  if (!filtering) {
    fillList($("list-suggestions"), state.matches, { suggestion: true });
    $("count-suggestions").textContent = String(state.matches.length);
    const empty = $("empty-suggestions");
    empty.hidden = state.matches.length !== 0;
    empty.textContent = state.fillable ? t("noEntriesForSite") : t("notAWebPage");
    $("list-suggestions").hidden = state.matches.length === 0;

    const favorites = state.all.filter((e) => e.favorite);
    $("sec-favorites").hidden = favorites.length === 0;
    fillList($("list-favorites"), favorites);
    $("count-favorites").textContent = String(favorites.length);
  }

  let list;
  let heading;
  let emptyText;
  if (state.query !== "") {
    list = filterEntries(state.searchResults, state.filter);
    heading = t("searchResultsHeading");
    emptyText = t("noSearchResults");
  } else if (filtering) {
    list = filterEntries(state.all, state.filter);
    heading = t("filteredHeading");
    emptyText = t("noFilterResults");
  } else {
    list = state.all;
    heading = t("allItemsHeading");
    emptyText = t("emptyVault");
  }
  $("all-heading-text").textContent = heading;
  $("count-all").textContent = String(list.length);
  $("empty-all").textContent = emptyText;
  $("empty-all").hidden = list.length !== 0;
  state.allList = list;
  state.allRendered = 0;
  $("list-all").replaceChildren();
  appendChunk();
  if (keepScroll) $("main").scrollTop = scroll;
}

function fillList(ul, entries, opts) {
  ul.replaceChildren(...entries.map((e) => entryRow(e, opts)));
}

function appendChunk() {
  const list = state.allList;
  if (state.allRendered >= list.length) return;
  const end = Math.min(list.length, state.allRendered + LIST_CHUNK_SIZE);
  const frag = document.createDocumentFragment();
  for (let i = state.allRendered; i < end; i += 1) frag.append(entryRow(list[i]));
  $("list-all").append(frag);
  state.allRendered = end;
}

// Lazy favicons: asked for when a row scrolls into view, in batches.
const favicons = new FaviconBatcher(async (hosts) => {
  const reply = await send("favicons", { hosts });
  return reply.ok ? reply.icons : {};
});

const faviconObserver = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      faviconObserver.unobserve(entry.target);
      loadFavicon(entry.target);
    }
  },
  { root: null, rootMargin: "120px" },
);

function loadFavicon(el) {
  const host = el.dataset.host;
  if (!host) return;
  favicons.get(host).then((url) => {
    if (!url || !el.isConnected) return;
    const img = document.createElement("img");
    img.alt = "";
    img.decoding = "async";
    img.src = url;
    img.addEventListener("load", () => el.replaceChildren(img), { once: true });
  });
}

function faviconFor(entry, { large = false } = {}) {
  const el = document.createElement("span");
  el.className = large ? "favicon large" : "favicon";
  el.setAttribute("aria-hidden", "true");
  const { letter, color } = avatarFor(entry.title || entry.url);
  const fallback = document.createElement("span");
  fallback.className = "avatar";
  fallback.textContent = letter;
  fallback.style.backgroundColor = color;
  el.append(fallback);
  const host = faviconHost(entry.url);
  if (host) {
    el.dataset.host = host;
    if (large) loadFavicon(el);
    else faviconObserver.observe(el);
  }
  return el;
}

function iconButton(name, label, onClick, className = "icon-button") {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  setLabel(b, label);
  b.append(icon(name));
  b.addEventListener("click", (ev) => {
    ev.stopPropagation();
    onClick(ev.currentTarget);
  });
  return b;
}

function entryRow(entry, { suggestion = false } = {}) {
  const title = entry.title || t("untitled");
  const li = document.createElement("li");
  li.className = "row";

  const main = document.createElement("button");
  main.type = "button";
  main.className = "row-main";
  main.setAttribute("aria-label", t("viewDetailsLabel", [title]));
  const text = document.createElement("span");
  text.className = "row-text";
  const name = document.createElement("span");
  name.className = "row-title";
  name.textContent = title;
  if (entry.favorite) {
    const star = icon("starFilled", 12);
    star.classList.add("fav-mark");
    name.append(star);
  }
  const user = document.createElement("span");
  user.className = "row-subtitle";
  user.textContent = entry.username || t("noUsername");
  text.append(name, user);
  main.append(faviconFor(entry), text);
  main.addEventListener("click", () => openDetails(entry));

  const actions = document.createElement("div");
  actions.className = "row-actions";
  if (suggestion && state.fillable) {
    const fill = document.createElement("button");
    fill.type = "button";
    fill.className = "pill suggested small";
    fill.textContent = t("fillButton");
    fill.setAttribute("aria-label", t("fillLabel", [title]));
    fill.addEventListener("click", (ev) => onFill(entry, ev.currentTarget));
    actions.append(fill);
  } else if (openableUrl(entry.url)) {
    actions.append(iconButton("external", t("openWebsiteLabel", [title]), () => openTab(entry.url)));
  }
  if (entry.username) {
    actions.append(iconButton("user", t("copyUsernameLabel", [title]), (b) => onCopy(entry, "username", b)));
  }
  actions.append(iconButton("key", t("copyPasswordLabel", [title]), (b) => onCopy(entry, "password", b)));
  if (entry.has_totp) {
    actions.append(iconButton("clock", t("copyCodeLabel", [title]), (b) => onCopy(entry, "totp", b)));
  }
  const more = iconButton("more", t("moreOptionsLabel", [title]), (b) => openRowMenu(entry, b, { suggestion }));
  more.setAttribute("aria-haspopup", "menu");
  more.setAttribute("aria-expanded", "false");
  actions.append(more);

  li.append(main, actions);
  return li;
}

/** Up/Down move between rows; from the search box, Down enters the list. */
function onVaultKey(event) {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  const rows = [...$("view-vault").querySelectorAll(".row-main")].filter((el) => el.offsetParent !== null);
  if (rows.length === 0) return;
  if (event.target === $("search")) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      rows[0].focus();
    }
    return;
  }
  const row = event.target.closest(".row");
  if (!row) return;
  const index = rows.indexOf(row.querySelector(".row-main"));
  if (index < 0) return;
  event.preventDefault();
  if (event.key === "ArrowDown") {
    if (index === rows.length - 1) appendChunk();
    const next = [...$("view-vault").querySelectorAll(".row-main")].filter((el) => el.offsetParent !== null)[index + 1];
    next?.focus();
  } else if (index === 0) {
    $("search").focus();
  } else {
    rows[index - 1].focus();
  }
}

async function runSearch(query) {
  const seq = ++state.searchSeq;
  state.query = query;
  if (query === "") {
    state.searchResults = [];
    renderVault();
    return;
  }
  const reply = await send("search", { query });
  if (seq !== state.searchSeq) return; // a newer search is running
  if (!reply.ok) {
    handleFailure(reply);
    return;
  }
  state.searchResults = reply.entries;
  renderVault();
}

const debouncedSearch = debounce((q) => runSearch(q), SEARCH_DEBOUNCE_MS);

// ── Row menu (⋮) ────────────────────────────────────────────────────────────

let rowMenuAnchor = null;

function menuItem(label, onSelect) {
  const b = document.createElement("button");
  b.type = "button";
  b.setAttribute("role", "menuitem");
  b.tabIndex = -1;
  b.textContent = label;
  b.addEventListener("click", () => {
    closeRowMenu();
    onSelect();
  });
  return b;
}

function openRowMenu(entry, anchor, { suggestion = false } = {}) {
  if (rowMenuAnchor === anchor) {
    closeRowMenu();
    return;
  }
  closeRowMenu();
  const menu = $("row-menu");
  const items = [
    menuItem(entry.favorite ? t("unfavoriteButton") : t("favoriteButton"), () => onToggleFavorite(entry)),
  ];
  if (suggestion && openableUrl(entry.url)) items.push(menuItem(t("openWebsiteButton"), () => openTab(entry.url)));
  if (entry.url) items.push(menuItem(t("copyWebsiteButton"), () => copyText(entry.url, t("websiteCopied"))));
  items.push(menuItem(t("viewDetailsButton"), () => openDetails(entry)));
  menu.replaceChildren(...items);
  menu.hidden = false;
  rowMenuAnchor = anchor;
  anchor.setAttribute("aria-expanded", "true");

  const r = anchor.getBoundingClientRect();
  const width = menu.offsetWidth;
  const height = menu.offsetHeight;
  const rtl = document.documentElement.dir === "rtl";
  let left = rtl ? r.left : r.right - width;
  left = Math.max(8, Math.min(left, window.innerWidth - width - 8));
  let top = r.bottom + 4;
  if (top + height > window.innerHeight - 8) top = Math.max(8, r.top - height - 4);
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
  items[0].focus();
}

function closeRowMenu({ restoreFocus = false } = {}) {
  const menu = $("row-menu");
  if (menu.hidden) return;
  menu.hidden = true;
  menu.replaceChildren();
  const anchor = rowMenuAnchor;
  rowMenuAnchor = null;
  if (anchor) {
    anchor.setAttribute("aria-expanded", "false");
    if (restoreFocus) anchor.focus();
  }
}

function onRowMenuKey(event) {
  const items = [...$("row-menu").querySelectorAll("[role=menuitem]")];
  const index = items.indexOf(document.activeElement);
  if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();
    closeRowMenu({ restoreFocus: true });
  } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    const step = event.key === "ArrowDown" ? 1 : -1;
    items[(index + step + items.length) % items.length]?.focus();
  } else if (event.key === "Home" || event.key === "End") {
    event.preventDefault();
    items[event.key === "Home" ? 0 : items.length - 1]?.focus();
  } else if (event.key === "Tab") {
    closeRowMenu({ restoreFocus: true });
  }
}

// ── Entry actions ───────────────────────────────────────────────────────────

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

async function copyText(value, message) {
  const ok = await writeClipboard(value);
  toast(ok ? message : t("copyFailed"), { error: !ok });
}

function updateEntry(id, changes) {
  for (const list of [state.all, state.matches, state.searchResults]) {
    for (const e of list) if (e.id === id) Object.assign(e, changes);
  }
}

async function onToggleFavorite(entry, el) {
  return withBusy(el, async () => {
    const reply = await send("toggleFavorite", { id: entry.id });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    updateEntry(entry.id, { favorite: reply.favorite });
    entry.favorite = reply.favorite;
    toast(reply.favorite ? t("addedToFavorites") : t("removedFromFavorites"));
    if (state.view === "view-vault") renderVault({ keepScroll: true });
    else state.vaultDirty = true;
    if (state.detail?.entry === entry) renderFavoriteButton();
  });
}

// ── Details ─────────────────────────────────────────────────────────────────

function openDetails(entry) {
  showView("view-details");
  state.detail = { entry, password: null, revealed: false, timer: null, totpSeq: 0, remaining: 0, period: 30 };
  setHeader({ title: t("detailsTitle"), back: true, lock: true });

  $("details-favicon").replaceWith(Object.assign(faviconFor(entry, { large: true }), { id: "details-favicon" }));
  $("details-title").textContent = entry.title || t("untitled");
  $("details-subtitle").textContent = hostOf(entry.url);

  $("field-username").hidden = entry.username === "";
  $("details-username").textContent = entry.username;
  renderDetailsPassword();

  const url = entry.url;
  $("field-url").hidden = url === "";
  $("details-url").textContent = url;
  $("details-open-url").hidden = openableUrl(url) === "";
  $("details-folder").textContent = entry.category || t("noFolder");

  $("field-totp").hidden = !entry.has_totp;
  $("details-totp").textContent = "";
  $("totp-seconds").textContent = "";
  if (entry.has_totp) loadTotp();

  $("details-fill").hidden = !(state.fillable && state.matchIds.has(entry.id));
  renderFavoriteButton();
  $("back").focus();
}

function hostOf(url) {
  const host = faviconHost(url);
  return host.startsWith("www.") ? host.slice(4) : host;
}

function closeDetails() {
  const d = state.detail;
  if (!d) return;
  clearInterval(d.timer);
  d.password = null;
  d.totpSeq += 1;
  state.detail = null;
  $("details-password").textContent = "";
  $("details-totp").textContent = "";
}

function renderFavoriteButton() {
  const d = state.detail;
  if (!d) return;
  const b = $("details-fav");
  const fav = d.entry.favorite === true;
  b.setAttribute("aria-pressed", String(fav));
  setLabel(b, fav ? t("unfavoriteButton") : t("favoriteButton"));
  b.replaceChildren(icon(fav ? "starFilled" : "star"));
  b.classList.toggle("active", fav);
}

function renderDetailsPassword() {
  const d = state.detail;
  const value = $("details-password");
  const reveal = $("details-reveal");
  const shown = d?.revealed && typeof d.password === "string";
  value.textContent = shown ? d.password : MASK;
  value.classList.toggle("masked", !shown);
  reveal.setAttribute("aria-pressed", String(Boolean(shown)));
  setLabel(reveal, shown ? t("hidePassword") : t("revealPassword"));
  reveal.replaceChildren(icon(shown ? "eyeOff" : "eye"));
}

async function onRevealPassword() {
  const d = state.detail;
  if (!d) return;
  if (d.revealed) {
    d.revealed = false;
    d.password = null;
    renderDetailsPassword();
    return;
  }
  await withBusy($("details-reveal"), async () => {
    const reply = await send("reveal", { id: d.entry.id });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    if (state.detail !== d) return;
    d.password = reply.password;
    reply.password = "";
    d.revealed = true;
    renderDetailsPassword();
  });
}

function formatCode(code) {
  if (/^\d{6}$/.test(code)) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (/^\d{8}$/.test(code)) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function renderRing() {
  const d = state.detail;
  if (!d) return;
  const fraction = totpFraction(d.remaining, d.period);
  $("totp-ring").style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - fraction));
  $("totp-ring-wrap").classList.toggle("ending", d.remaining <= 5);
  $("totp-seconds").textContent = String(Math.max(0, Math.ceil(d.remaining)));
}

async function loadTotp() {
  const d = state.detail;
  if (!d) return;
  const seq = ++d.totpSeq;
  clearInterval(d.timer);
  const reply = await send("totp", { id: d.entry.id });
  if (state.detail !== d || seq !== d.totpSeq) return;
  if (!reply.ok) {
    handleFailure(reply);
    return;
  }
  $("details-totp").textContent = formatCode(reply.code);
  d.remaining = reply.remaining;
  d.period = reply.period;
  renderRing();
  d.timer = setInterval(() => {
    if (state.detail !== d) return;
    d.remaining -= 1;
    if (d.remaining <= 0) {
      loadTotp();
      return;
    }
    renderRing();
  }, 1000);
}

// ── Add ─────────────────────────────────────────────────────────────────────

function openAdd() {
  showView("view-add");
  setHeader({ title: t("newLoginTitle"), back: true, lock: true });
  resetAddForm();
  $("add-title").value = state.host;
  $("add-url").value = state.origin;
  $("add-folder-list").replaceChildren(...state.folders.map((name) => option(name, name)));
  (state.host ? $("add-username") : $("add-title")).focus();
}

function resetAddForm() {
  $("add-form").reset();
  $("add-password").type = "password";
  $("add-error").textContent = "";
  const reveal = $("add-reveal");
  reveal.setAttribute("aria-pressed", "false");
  setLabel(reveal, t("revealPassword"));
  reveal.replaceChildren(icon("eye"));
}

function onAddReveal() {
  const input = $("add-password");
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  const reveal = $("add-reveal");
  reveal.setAttribute("aria-pressed", String(show));
  setLabel(reveal, show ? t("hidePassword") : t("revealPassword"));
  reveal.replaceChildren(icon(show ? "eyeOff" : "eye"));
}

function onAddGenerate() {
  return withBusy($("add-generate"), async () => {
    const reply = await send("generate", { options: state.gen.options });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    $("add-password").value = reply.value;
    reply.value = "";
    toast(t("passwordGenerated"));
  });
}

async function onAddSubmit(event) {
  event.preventDefault();
  const title = $("add-title").value.trim();
  const password = $("add-password").value;
  if (title === "") {
    $("add-error").textContent = t("nameRequired");
    $("add-title").focus();
    return;
  }
  if (password === "") {
    $("add-error").textContent = t("passwordRequired");
    $("add-password").focus();
    return;
  }
  $("add-error").textContent = "";
  await withBusy($("add-save"), async () => {
    const reply = await send("add", {
      title,
      username: $("add-username").value,
      password,
      url: $("add-url").value,
      category: $("add-folder").value,
    });
    if (!reply.ok) {
      if (reply.code === "locked" || ["not_installed", "disabled", "no_vault"].includes(reply.code)) {
        handleFailure(reply);
      } else {
        $("add-error").textContent = errorText(reply);
      }
      return;
    }
    resetAddForm();
    toast(t("saved"));
    state.vaultLoaded = false;
    state.tab = "vault";
    setTabbar(true);
    await loadVault();
    const added = reply.id !== null ? state.all.find((e) => e.id === reply.id) : null;
    if (added) openDetails(added);
  });
}

function onBack() {
  if (state.view === "view-details" || state.view === "view-add") showTab("vault");
}

// ── Generator ───────────────────────────────────────────────────────────────

function showGenerator() {
  setHeader({ title: t("tabGenerator"), lock: true });
  showView("view-generator");
  syncGeneratorControls();
  if (state.gen.value === "") regenerate();
}

function syncGeneratorControls() {
  const o = state.gen.options;
  for (const b of $("gen-kind").querySelectorAll("[role=radio]")) {
    const on = b.dataset.kind === o.kind;
    b.setAttribute("aria-checked", String(on));
    b.tabIndex = on ? 0 : -1;
  }
  $("gen-opts-password").hidden = o.kind !== "password";
  $("gen-opts-passphrase").hidden = o.kind !== "passphrase";
  $("gen-opts-pin").hidden = o.kind !== "pin";
  $("gen-length").value = $("gen-length-num").value = String(o.password.length);
  $("gen-upper").checked = o.password.uppercase;
  $("gen-lower").checked = o.password.lowercase;
  $("gen-digits").checked = o.password.digits;
  $("gen-symbols").checked = o.password.symbols;
  $("gen-ambiguous").checked = o.password.avoidAmbiguous;
  $("gen-words").value = $("gen-words-num").value = String(o.passphrase.words);
  if (document.activeElement !== $("gen-separator")) $("gen-separator").value = o.passphrase.separator;
  $("gen-capitalize").checked = o.passphrase.capitalize;
  $("gen-number").checked = o.passphrase.number;
  $("gen-pin-length").value = $("gen-pin-length-num").value = String(o.pin.length);
}

function readGeneratorControls() {
  const o = state.gen.options;
  return normalizeGeneratorOptions({
    kind: o.kind,
    password: {
      length: $("gen-length").value,
      uppercase: $("gen-upper").checked,
      lowercase: $("gen-lower").checked,
      digits: $("gen-digits").checked,
      symbols: $("gen-symbols").checked,
      avoidAmbiguous: $("gen-ambiguous").checked,
    },
    passphrase: {
      words: $("gen-words").value,
      separator: $("gen-separator").value,
      capitalize: $("gen-capitalize").checked,
      number: $("gen-number").checked,
    },
    pin: { length: $("gen-pin-length").value },
  });
}

function onGeneratorChange() {
  state.gen.options = readGeneratorControls();
  syncGeneratorControls();
  storageSet(STORAGE_GENERATOR, state.gen.options);
  regenerate();
}

const debouncedGeneratorChange = debounce(onGeneratorChange, 120);

function bindRange(rangeId, numberId, [min, max]) {
  const range = $(rangeId);
  const num = $(numberId);
  range.addEventListener("input", () => {
    num.value = range.value;
    debouncedGeneratorChange();
  });
  num.addEventListener("change", () => {
    const n = Math.min(max, Math.max(min, Math.round(Number(num.value) || min)));
    num.value = range.value = String(n);
    onGeneratorChange();
  });
}

/** Keeps at least one character class switched on. */
function onClassToggle(event) {
  const classes = ["gen-upper", "gen-lower", "gen-digits", "gen-symbols"].map($);
  if (!classes.some((c) => c.checked)) {
    event.target.checked = true;
    toast(t("oneClassRequired"));
    return;
  }
  onGeneratorChange();
}

function onKindSelect(kind) {
  if (kind === state.gen.options.kind) return;
  state.gen.options = normalizeGeneratorOptions({ ...state.gen.options, kind });
  syncGeneratorControls();
  storageSet(STORAGE_GENERATOR, state.gen.options);
  regenerate();
}

function onKindKey(event) {
  const radios = [...$("gen-kind").querySelectorAll("[role=radio]")];
  const index = radios.indexOf(event.target);
  if (index < 0) return;
  let next = -1;
  if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (index + 1) % radios.length;
  else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (index - 1 + radios.length) % radios.length;
  if (next < 0) return;
  event.preventDefault();
  radios[next].focus();
  onKindSelect(radios[next].dataset.kind);
}

async function regenerate() {
  const seq = ++state.gen.seq;
  const reply = await send("generate", { options: state.gen.options });
  if (seq !== state.gen.seq) return;
  if (!reply.ok) {
    handleFailure(reply);
    return;
  }
  state.gen.value = reply.value;
  reply.value = "";
  renderGenerated();
}

function renderGenerated() {
  const out = $("gen-value");
  const parts = [];
  for (const ch of Array.from(state.gen.value)) {
    const span = document.createElement("span");
    span.textContent = ch;
    if (/\d/.test(ch)) span.className = "ch-digit";
    else if (!/\p{L}/u.test(ch)) span.className = "ch-symbol";
    parts.push(span);
  }
  out.replaceChildren(...parts);
}

function resetGenerated() {
  state.gen.value = "";
  state.gen.seq += 1;
  $("gen-value").replaceChildren();
}

function onGenCopy() {
  if (state.gen.value === "") return;
  copyText(state.gen.value, t("passwordCopied"));
}

function onGenFill() {
  if (state.gen.value === "") return;
  return withBusy($("gen-fill"), async () => {
    const reply = await send("fillPassword", { tabId: state.tabId, password: state.gen.value });
    if (!reply.ok) {
      handleFailure(reply);
      return;
    }
    if (reply.filled > 0) toast(t("filled"));
    else toast(t("noPasswordField"), { error: true });
  });
}

// ── Settings ────────────────────────────────────────────────────────────────

async function showSettings() {
  setHeader({ title: t("tabSettings"), lock: true });
  showView("view-settings");
  $("settings-version").textContent = api.runtime.getManifest().version;
  const reply = await send("inlineState");
  state.inlineEnabled = reply.ok && reply.enabled === true;
  $("settings-inline").checked = state.inlineEnabled;
  try {
    const commands = (await api.commands?.getAll?.()) ?? [];
    const action = commands.find((c) => c.name === "_execute_action");
    $("settings-shortcut").textContent = action?.shortcut || t("shortcutNotSet");
  } catch {
    // Keep the default text.
  }
}

/**
 * Turns the inline suggestions on. permissions.request must run straight
 * from the click (before any await), or the browser refuses it.
 */
function enableInline() {
  let request;
  try {
    request = api.permissions.request({ origins: [...INLINE_MATCHES] });
  } catch (err) {
    request = Promise.reject(err);
  }
  return Promise.resolve(request)
    .then(async (granted) => {
      if (!granted) {
        toast(t("permissionDenied"), { error: true });
        return false;
      }
      const reply = await send("inlineSet", { enabled: true });
      if (!reply.ok) {
        toast(errorText(reply), { error: true });
        return false;
      }
      toast(t("inlineEnabledToast"));
      return true;
    })
    .catch(() => {
      toast(t("permissionDenied"), { error: true });
      return false;
    })
    .then((enabled) => {
      state.inlineEnabled = enabled;
      $("settings-inline").checked = enabled;
      if (enabled) $("inline-hint").hidden = true;
      return enabled;
    });
}

async function onInlineToggle(event) {
  if (event.target.checked) {
    await enableInline();
    return;
  }
  const reply = await send("inlineSet", { enabled: false });
  state.inlineEnabled = !reply.ok;
  $("settings-inline").checked = state.inlineEnabled;
  if (!reply.ok) toast(errorText(reply), { error: true });
}

function onHintEnable() {
  enableInline();
}

function onHintDismiss() {
  state.hintDismissed = true;
  $("inline-hint").hidden = true;
  storageSet(STORAGE_HINT, true);
  $("search").focus();
}

// ── Lock / app ──────────────────────────────────────────────────────────────

function onLock(event) {
  return withBusy(event?.currentTarget ?? null, async () => {
    const reply = await send("lock");
    if (!reply.ok && handleFailure(reply)) return;
    state.vaultLoaded = false;
    state.all = [];
    state.matches = [];
    state.searchResults = [];
    showLocked();
    toast(t("vaultLocked"));
  });
}

function onOpenApp(event) {
  return withBusy(event?.currentTarget ?? null, async () => {
    const reply = await send("openApp");
    if (!reply.ok) toast(errorText(reply), { error: true });
  });
}

// ── Start ───────────────────────────────────────────────────────────────────

function wipe() {
  resetGenerated();
  closeDetails();
  $("unlock-input").value = "";
  $("add-password").value = "";
}

async function init() {
  applyI18n();
  applyIcons();

  $("unlock-form").addEventListener("submit", onUnlock);
  $("unlock-switch").addEventListener("click", onUnlockSwitch);
  $("locked-open-app").addEventListener("click", onOpenApp);
  $("message-open-app").addEventListener("click", onOpenApp);
  $("retry").addEventListener("click", refresh);
  $("lock").addEventListener("click", onLock);
  $("back").addEventListener("click", onBack);
  $("add").addEventListener("click", openAdd);

  for (const b of $("tabbar").querySelectorAll("[role=tab]")) {
    b.addEventListener("click", () => showTab(b.dataset.tab));
  }
  $("tabbar").addEventListener("keydown", onTabKey);

  // Vault
  $("search").addEventListener("input", (ev) => debouncedSearch(ev.target.value.trim()));
  $("search").addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && ev.target.value !== "") {
      ev.preventDefault();
      ev.target.value = "";
      debouncedSearch.cancel();
      runSearch("");
    }
  });
  $("filter-folder").addEventListener("change", (ev) => {
    state.filter.folder = ev.target.value;
    renderVault();
  });
  $("filter-type").addEventListener("change", (ev) => {
    state.filter.type = ev.target.value;
    renderVault();
  });
  $("view-vault").addEventListener("keydown", onVaultKey);
  $("inline-hint-enable").addEventListener("click", onHintEnable);
  $("inline-hint-dismiss").addEventListener("click", onHintDismiss);
  new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) appendChunk();
  }, { root: null, rootMargin: "200px" }).observe($("all-sentinel"));

  // Row menu
  $("row-menu").addEventListener("keydown", onRowMenuKey);
  document.addEventListener("pointerdown", (ev) => {
    if (!$("row-menu").hidden && !$("row-menu").contains(ev.target) && !rowMenuAnchor?.contains(ev.target)) closeRowMenu();
  });
  $("main").addEventListener("scroll", () => closeRowMenu(), { passive: true });

  // Details
  $("details-copy-username").addEventListener("click", (ev) => state.detail && onCopy(state.detail.entry, "username", ev.currentTarget));
  $("details-copy-password").addEventListener("click", (ev) => state.detail && onCopy(state.detail.entry, "password", ev.currentTarget));
  $("details-copy-totp").addEventListener("click", (ev) => state.detail && onCopy(state.detail.entry, "totp", ev.currentTarget));
  $("details-reveal").addEventListener("click", onRevealPassword);
  $("details-open-url").addEventListener("click", () => state.detail && openTab(state.detail.entry.url));
  $("details-copy-url").addEventListener("click", () => state.detail && copyText(state.detail.entry.url, t("websiteCopied")));
  $("details-fav").addEventListener("click", (ev) => state.detail && onToggleFavorite(state.detail.entry, ev.currentTarget));
  $("details-fill").addEventListener("click", (ev) => state.detail && onFill(state.detail.entry, ev.currentTarget));

  // Add
  $("add-form").addEventListener("submit", onAddSubmit);
  $("add-cancel").addEventListener("click", onBack);
  $("add-reveal").addEventListener("click", onAddReveal);
  $("add-generate").addEventListener("click", onAddGenerate);

  // Generator
  $("gen-regen").addEventListener("click", regenerate);
  $("gen-copy").addEventListener("click", onGenCopy);
  $("gen-fill").addEventListener("click", onGenFill);
  for (const b of $("gen-kind").querySelectorAll("[role=radio]")) {
    b.addEventListener("click", () => onKindSelect(b.dataset.kind));
  }
  $("gen-kind").addEventListener("keydown", onKindKey);
  bindRange("gen-length", "gen-length-num", GENERATOR_RANGES.passwordLength);
  bindRange("gen-words", "gen-words-num", GENERATOR_RANGES.words);
  bindRange("gen-pin-length", "gen-pin-length-num", GENERATOR_RANGES.pinLength);
  for (const id of ["gen-upper", "gen-lower", "gen-digits", "gen-symbols"]) $(id).addEventListener("change", onClassToggle);
  for (const id of ["gen-ambiguous", "gen-capitalize", "gen-number"]) $(id).addEventListener("change", onGeneratorChange);
  $("gen-separator").addEventListener("input", debouncedGeneratorChange);

  // Settings
  $("settings-lock").addEventListener("click", onLock);
  $("settings-open-app").addEventListener("click", onOpenApp);
  $("settings-inline").addEventListener("change", onInlineToggle);
  $("settings-help").addEventListener("click", () => openTab(HELP_URL));
  $("settings-privacy").addEventListener("click", () => openTab(PRIVACY_URL));

  window.addEventListener("pagehide", wipe);

  state.gen.options = normalizeGeneratorOptions(await storageGet(STORAGE_GENERATOR));
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
