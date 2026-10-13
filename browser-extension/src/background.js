// Ashy Pass background script (Chrome service worker / Firefox event page).
//
// Owns the single native-messaging port to `ashypass-native-host` and answers
// the popup, the inline suggestions menu and the inline content script. It
// never stores secrets: every value is asked from the host when the user
// clicks, handed on, and dropped.

import {
  ALLOWED_TYPES,
  COPY_FIELDS,
  ExtError,
  FIELD_LIMITS,
  HOST_NAME,
  INLINE_MATCHES,
  INLINE_SCRIPT_ID,
  InlineTokens,
  MAX_QUERY_LENGTH,
  REQUEST_TIMEOUT_MS,
  RequestTracker,
  classifyDisconnect,
  countFilled,
  generatorRequest,
  hostForDisplay,
  isFillableUrl,
  isValidId,
  pageOriginOf,
  sanitizeEntries,
  sanitizeFolders,
  sanitizeHosts,
  sanitizeIcons,
  sanitizeNewEntry,
  senderKind,
  stateFromStatus,
  toErrorResult,
} from "./lib/helpers.js";
import { fillCredentials, fillPasswordFields } from "./lib/fill.js";

const api = globalThis.browser ?? globalThis.chrome;

// ── Native port ─────────────────────────────────────────────────────────────

let port = null;
const tracker = new RequestTracker({ timeoutMs: REQUEST_TIMEOUT_MS });

function connect() {
  if (port) return port;
  let p;
  try {
    p = api.runtime.connectNative(HOST_NAME);
  } catch (err) {
    const text = String(err?.message ?? err);
    throw new ExtError(classifyDisconnect(text), text);
  }
  p.onMessage.addListener((reply) => {
    tracker.settle(reply);
  });
  p.onDisconnect.addListener((closed) => {
    // Chrome reports the reason in runtime.lastError, Firefox in port.error.
    const text = api.runtime.lastError?.message ?? closed?.error?.message ?? "";
    if (port === p) port = null;
    const code = classifyDisconnect(text);
    tracker.failAll(new ExtError(code, text || "The connection to Ashy Pass was closed."));
  });
  port = p;
  return p;
}

/** Sends one request to the host and waits for the reply with the same rid. */
async function host(cmd, fields = {}) {
  const p = connect();
  const { rid, message, promise } = tracker.create(cmd, fields);
  try {
    p.postMessage(message);
  } catch (err) {
    const text = String(err?.message ?? err);
    if (port === p) port = null;
    tracker.fail(rid, new ExtError(classifyDisconnect(text), text));
  } finally {
    // Do not keep secrets (e.g. the master password) referenced from here.
    for (const key of Object.keys(message)) delete message[key];
  }
  return promise;
}

// ── Shared steps ────────────────────────────────────────────────────────────

async function tabUrl(tabId) {
  if (!Number.isInteger(tabId)) throw new ExtError("invalid", "Missing tab.");
  const tab = await api.tabs.get(tabId);
  return typeof tab?.url === "string" ? tab.url : "";
}

const STATE_ERRORS = ["not_installed", "disabled", "no_vault", "locked"];

/** One of unlocked / locked / disabled / no_vault / not_installed, plus pin_available. */
async function currentState() {
  try {
    const reply = await host("status");
    return { state: stateFromStatus(reply), pinAvailable: reply.pin_available === true };
  } catch (err) {
    if (STATE_ERRORS.includes(err?.code)) return { state: err.code, pinAvailable: false };
    throw err;
  }
}

/**
 * Asks the host for the credentials of `id` on `url` (it refuses with
 * no_match unless the entry belongs to that site) and injects the filler.
 * `target` is an executeScript target; the filler itself also refuses every
 * frame whose origin is not the page's.
 */
async function fillEntry(id, url, target) {
  const origin = pageOriginOf(url);
  if (origin === null) throw new ExtError("not_web_page", "Not a web page.");
  const reply = await host("fill", { id, url });
  let username = typeof reply.username === "string" ? reply.username : "";
  let password = typeof reply.password === "string" ? reply.password : "";
  reply.username = "";
  reply.password = "";
  let results;
  try {
    results = await api.scripting.executeScript({ target, func: fillCredentials, args: [username, password, origin] });
  } catch (err) {
    throw new ExtError("cannot_access", String(err?.message ?? err));
  } finally {
    username = "";
    password = "";
  }
  return countFilled(results);
}

// ── Inline suggestions (content script, on unless turned off) ───────────────
//
// Like other password managers, the extension asks for access to http(s)
// sites at install, so the suggestions work right away. Turning them off in
// Settings only unregisters the script (the access is a required
// permission); the choice is kept in storage.local.

const INLINE_PERMISSIONS = Object.freeze({ origins: [...INLINE_MATCHES] });
const tokens = new InlineTokens();
let pendingView = null; // {view, tabId, expires}: "Add login" from the inline menu
const PENDING_VIEW_MS = 60_000;

async function inlinePermitted() {
  try {
    return (await api.permissions.contains(INLINE_PERMISSIONS)) === true;
  } catch {
    return false;
  }
}

async function inlineRegistered() {
  try {
    const list = await api.scripting.getRegisteredContentScripts({ ids: [INLINE_SCRIPT_ID] });
    return Array.isArray(list) && list.length > 0;
  } catch {
    return false;
  }
}

// Registration changes run one after another (startup, permission events and
// the Settings toggle may overlap).
let inlineQueue = Promise.resolve();
function serial(fn) {
  const run = inlineQueue.then(fn, fn);
  inlineQueue = run.catch(() => {});
  return run;
}

const INLINE_OFF_KEY = "inlineOff";

async function inlineTurnedOff() {
  try {
    const stored = await api.storage.local.get(INLINE_OFF_KEY);
    return stored?.[INLINE_OFF_KEY] === true;
  } catch {
    return false;
  }
}

function syncInline() {
  return serial(async () => {
    const permitted = (await inlinePermitted()) && !(await inlineTurnedOff());
    const registered = await inlineRegistered();
    if (permitted && !registered) {
      await api.scripting.registerContentScripts([
        {
          id: INLINE_SCRIPT_ID,
          js: ["inline/content.js"],
          matches: [...INLINE_MATCHES],
          allFrames: true,
          runAt: "document_idle",
        },
      ]);
    } else if (!permitted && registered) {
      await api.scripting.unregisterContentScripts({ ids: [INLINE_SCRIPT_ID] });
    }
    return permitted;
  });
}

const inlineHandlers = {
  /** Content script: a login field was focused; returns an opening token. */
  async inlineOpen(msg, sender) {
    const tabId = sender.tab?.id;
    const frameId = Number.isInteger(sender.frameId) ? sender.frameId : 0;
    const frameOrigin = pageOriginOf(sender.url);
    const topOrigin = pageOriginOf(sender.tab?.url);
    // Never in a frame whose origin differs from the page's (the filler would
    // refuse it anyway); never on non-web pages.
    if (frameOrigin === null || topOrigin === null || frameOrigin !== topOrigin) {
      throw new ExtError("cross_origin", "Not available in this frame.");
    }
    return { ok: true, token: tokens.issue({ tabId, frameId, origin: frameOrigin }) };
  },

  /** Menu frame: state and suggestions for the tab that opened it. */
  async inlineMenuState(msg, sender) {
    const rec = tokens.claim(msg.token, { tabId: sender.tab?.id, menuFrameId: sender.frameId });
    if (!rec) throw new ExtError("bad_token", "This menu has expired.");
    const { state, pinAvailable } = await currentState();
    const url = await tabUrl(rec.tabId);
    if (pageOriginOf(url) !== rec.origin) throw new ExtError("bad_token", "The page changed.");
    const shown = hostForDisplay(url);
    if (state !== "unlocked") return { ok: true, state, pinAvailable, host: shown, entries: [] };
    const reply = await host("match_url", { url });
    return { ok: true, state, pinAvailable, host: shown, entries: sanitizeEntries(reply.entries) };
  },

  /** Menu frame: fill one entry into the frame that opened the menu (once). */
  async inlineFill(msg, sender) {
    const rec = tokens.consume(msg.token, { tabId: sender.tab?.id, menuFrameId: sender.frameId });
    if (!rec) throw new ExtError("bad_token", "This menu has expired.");
    if (!isValidId(msg.id)) throw new ExtError("invalid", "Missing entry.");
    const url = await tabUrl(rec.tabId);
    if (pageOriginOf(url) !== rec.origin) throw new ExtError("bad_token", "The page changed.");
    const filled = await fillEntry(msg.id, url, { tabId: rec.tabId, frameIds: [rec.frameId] });
    return { ok: true, filled };
  },

  /** Menu frame: open the toolbar popup (to unlock, or on the Add view). */
  async inlineOpenPopup(msg, sender) {
    const rec = tokens.claim(msg.token, { tabId: sender.tab?.id, menuFrameId: sender.frameId });
    if (!rec) throw new ExtError("bad_token", "This menu has expired.");
    pendingView = msg.view === "add" ? { view: "add", tabId: rec.tabId, expires: Date.now() + PENDING_VIEW_MS } : null;
    // The menu first tries action.openPopup() itself, from the click (Firefox
    // needs the user gesture); `open: false` only records the view.
    if (msg.open === false) return { ok: true, opened: false };
    try {
      await api.action.openPopup();
      return { ok: true, opened: true };
    } catch {
      return { ok: true, opened: false };
    }
  },
};

// ── Popup API ───────────────────────────────────────────────────────────────

function requireId(msg) {
  if (!isValidId(msg.id)) throw new ExtError("invalid", "Missing entry.");
  return msg.id;
}

const handlers = {
  async status() {
    const { state, pinAvailable } = await currentState();
    return { ok: true, state, pinAvailable };
  },

  async unlock(msg) {
    let password = typeof msg.password === "string" ? msg.password : "";
    msg.password = "";
    if (password === "") throw new ExtError("bad_password", "Empty password.");
    try {
      await host("unlock", { password });
    } finally {
      password = "";
    }
    return { ok: true };
  },

  async unlockPin(msg) {
    let pin = typeof msg.pin === "string" ? msg.pin : "";
    msg.pin = "";
    if (pin === "") throw new ExtError("bad_pin", "Empty PIN.");
    try {
      await host("unlock_pin", { pin });
    } finally {
      pin = "";
    }
    return { ok: true };
  },

  async lock() {
    await host("lock");
    return { ok: true };
  },

  async openApp() {
    await host("open_app");
    return { ok: true };
  },

  async match(msg) {
    const url = await tabUrl(msg.tabId);
    if (!isFillableUrl(url)) {
      return { ok: true, host: "", origin: "", fillable: false, entries: [] };
    }
    const reply = await host("match_url", { url });
    return {
      ok: true,
      host: hostForDisplay(url),
      origin: pageOriginOf(url),
      fillable: true,
      entries: sanitizeEntries(reply.entries),
    };
  },

  async list() {
    const reply = await host("list");
    return { ok: true, entries: sanitizeEntries(reply.entries) };
  },

  async search(msg) {
    const query = typeof msg.query === "string" ? msg.query.trim().slice(0, MAX_QUERY_LENGTH) : "";
    if (query === "") return { ok: true, entries: [] };
    const reply = await host("search", { query });
    return { ok: true, entries: sanitizeEntries(reply.entries) };
  },

  async folders() {
    const reply = await host("folders");
    return { ok: true, folders: sanitizeFolders(reply.folders) };
  },

  async favicons(msg) {
    const hosts = sanitizeHosts(msg.hosts);
    if (hosts.length === 0) return { ok: true, icons: {} };
    const reply = await host("favicons", { hosts });
    return { ok: true, icons: sanitizeIcons(reply.icons, hosts) };
  },

  async fill(msg) {
    const id = requireId(msg);
    const url = await tabUrl(msg.tabId);
    const filled = await fillEntry(id, url, { tabId: msg.tabId, allFrames: true });
    return { ok: true, filled };
  },

  async fillPassword(msg) {
    let password = typeof msg.password === "string" ? msg.password : "";
    msg.password = "";
    if (password === "" || password.length > FIELD_LIMITS.password) throw new ExtError("invalid", "Missing password.");
    const url = await tabUrl(msg.tabId);
    const origin = pageOriginOf(url);
    if (origin === null) throw new ExtError("not_web_page", "Not a web page.");
    let results;
    try {
      results = await api.scripting.executeScript({
        target: { tabId: msg.tabId, allFrames: true },
        func: fillPasswordFields,
        args: [password, origin],
      });
    } catch (err) {
      throw new ExtError("cannot_access", String(err?.message ?? err));
    } finally {
      password = "";
    }
    return { ok: true, filled: countFilled(results) };
  },

  async copy(msg) {
    const id = requireId(msg);
    if (!COPY_FIELDS.includes(msg.field)) throw new ExtError("invalid", "Unknown field.");
    if (msg.field === "totp") {
      const reply = await host("totp", { id });
      return { ok: true, value: String(reply.code ?? ""), remaining: reply.remaining };
    }
    const reply = await host("get", { id });
    const value = String(reply.entry?.[msg.field] ?? "");
    if (reply.entry) reply.entry.password = "";
    return { ok: true, value };
  },

  /** The password of one entry, for the reveal toggle of the details view. */
  async reveal(msg) {
    const id = requireId(msg);
    const reply = await host("get", { id });
    const password = String(reply.entry?.password ?? "");
    if (reply.entry) reply.entry.password = "";
    return { ok: true, password };
  },

  async totp(msg) {
    const id = requireId(msg);
    const reply = await host("totp", { id });
    const num = (v) => (Number.isFinite(v) && v >= 0 ? v : 0);
    return { ok: true, code: String(reply.code ?? ""), remaining: num(reply.remaining), period: num(reply.period) || 30 };
  },

  async add(msg) {
    const fields = sanitizeNewEntry(msg);
    msg.password = "";
    try {
      const reply = await host("add", fields);
      return { ok: true, id: isValidId(reply.id) ? reply.id : null };
    } finally {
      fields.password = "";
    }
  },

  async toggleFavorite(msg) {
    const id = requireId(msg);
    const reply = await host("toggle_favorite", { id });
    return { ok: true, favorite: reply.favorite === true };
  },

  async generate(msg) {
    const options = msg.options && typeof msg.options === "object" ? msg.options : { kind: msg.kind };
    const reply = await host("generate", generatorRequest(options));
    return { ok: true, value: String(reply.password ?? "") };
  },

  async inlineState() {
    return { ok: true, enabled: await syncInline() };
  },

  /** Settings toggle. The popup requests the permission itself (it needs the click). */
  async inlineSet(msg) {
    if (msg.enabled === true) {
      await api.storage.local.remove(INLINE_OFF_KEY);
      if (!(await syncInline())) throw new ExtError("permission_denied", "Permission not granted.");
      return { ok: true, enabled: true };
    }
    // The site access is a required permission now: just switch the
    // feature off and remember it.
    await api.storage.local.set({ [INLINE_OFF_KEY]: true });
    await syncInline();
    return { ok: true, enabled: false };
  },

  async takePendingView(msg) {
    const pending = pendingView;
    pendingView = null;
    if (!pending || pending.expires < Date.now() || pending.tabId !== msg.tabId) return { ok: true, view: null };
    return { ok: true, view: pending.view };
  },
};

// ── Wiring ──────────────────────────────────────────────────────────────────

function handlerFor(kind, type) {
  if (kind === "page") return Object.hasOwn(handlers, type) ? handlers[type] : null;
  if (kind === "content" || kind === "menu") {
    if (!ALLOWED_TYPES[kind].has(type)) return null;
    if (Object.hasOwn(inlineHandlers, type)) return inlineHandlers[type];
    return Object.hasOwn(handlers, type) ? handlers[type] : null;
  }
  return null;
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return false;
  const kind = senderKind(sender, api.runtime.id, api.runtime.getURL(""));
  const handler = handlerFor(kind, msg.type);
  if (!handler) return false;
  const reply = Promise.resolve()
    .then(() => handler(msg, sender))
    .catch(toErrorResult);
  // The `browser` namespace (Firefox, and recent Chromium which now exposes
  // it too) answers with the promise a listener returns; the `chrome`
  // namespace of older Chrome only through sendResponse + `return true`.
  if (api === globalThis.browser) return reply;
  reply.then(sendResponse);
  return true;
});

api.tabs?.onRemoved?.addListener((tabId) => tokens.revokeTab(tabId));
api.permissions?.onAdded?.addListener(() => syncInline().catch(() => {}));
api.permissions?.onRemoved?.addListener(() => syncInline().catch(() => {}));
// Re-register the inline script if the permission is there but the
// registration was lost (e.g. a browser that does not persist it).
syncInline().catch(() => {});
