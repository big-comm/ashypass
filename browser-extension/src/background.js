// Ashy Pass background script (Chrome service worker / Firefox event page).
//
// Owns the single native-messaging port to `ashypass-native-host` and answers
// the popup. It never stores secrets: every value is asked from the host when
// the user clicks, handed on, and dropped.

import {
  COPY_FIELDS,
  ExtError,
  GENERATE_KINDS,
  HOST_NAME,
  MAX_QUERY_LENGTH,
  REQUEST_TIMEOUT_MS,
  RequestTracker,
  classifyDisconnect,
  countFilled,
  hostForDisplay,
  isFillableUrl,
  isValidId,
  pageOriginOf,
  sanitizeEntries,
  stateFromStatus,
  toErrorResult,
} from "./lib/helpers.js";
import { fillCredentials } from "./lib/fill.js";

const api = globalThis.browser ?? globalThis.chrome;

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

async function tabUrl(tabId) {
  if (!Number.isInteger(tabId)) throw new ExtError("invalid", "Missing tab.");
  const tab = await api.tabs.get(tabId);
  return typeof tab?.url === "string" ? tab.url : "";
}

const handlers = {
  async status() {
    try {
      const reply = await host("status");
      return { ok: true, state: stateFromStatus(reply) };
    } catch (err) {
      if (["not_installed", "disabled", "no_vault", "locked"].includes(err?.code)) {
        return { ok: true, state: err.code };
      }
      throw err;
    }
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

  async lock() {
    await host("lock");
    return { ok: true };
  },

  async match(msg) {
    const url = await tabUrl(msg.tabId);
    if (!isFillableUrl(url)) {
      return { ok: true, host: "", fillable: false, entries: [] };
    }
    const reply = await host("match_url", { url });
    return { ok: true, host: hostForDisplay(url), fillable: true, entries: sanitizeEntries(reply.entries) };
  },

  async search(msg) {
    const query = typeof msg.query === "string" ? msg.query.trim().slice(0, MAX_QUERY_LENGTH) : "";
    if (query === "") return { ok: true, entries: [] };
    const reply = await host("search", { query });
    return { ok: true, entries: sanitizeEntries(reply.entries) };
  },

  async fill(msg) {
    if (!isValidId(msg.id)) throw new ExtError("invalid", "Missing entry.");
    const url = await tabUrl(msg.tabId);
    const origin = pageOriginOf(url);
    if (origin === null) throw new ExtError("not_web_page", "Not a web page.");

    // The host only answers when the entry belongs to this URL (no_match otherwise).
    const reply = await host("fill", { id: msg.id, url });
    let username = typeof reply.username === "string" ? reply.username : "";
    let password = typeof reply.password === "string" ? reply.password : "";
    reply.username = "";
    reply.password = "";
    let results;
    try {
      results = await api.scripting.executeScript({
        target: { tabId: msg.tabId, allFrames: true },
        func: fillCredentials,
        args: [username, password, origin],
      });
    } catch (err) {
      throw new ExtError("cannot_access", String(err?.message ?? err));
    } finally {
      username = "";
      password = "";
    }
    return { ok: true, filled: countFilled(results) };
  },

  async copy(msg) {
    if (!isValidId(msg.id)) throw new ExtError("invalid", "Missing entry.");
    if (!COPY_FIELDS.includes(msg.field)) throw new ExtError("invalid", "Unknown field.");
    if (msg.field === "totp") {
      const reply = await host("totp", { id: msg.id });
      return { ok: true, value: String(reply.code ?? ""), remaining: reply.remaining };
    }
    const reply = await host("get", { id: msg.id });
    const value = String(reply.entry?.[msg.field] ?? "");
    if (reply.entry) reply.entry.password = "";
    return { ok: true, value };
  },

  async generate(msg) {
    const kind = GENERATE_KINDS.includes(msg.kind) ? msg.kind : "password";
    const reply = await host("generate", { kind });
    return { ok: true, value: String(reply.password ?? "") };
  },
};

/**
 * Only our own extension pages (the popup) may talk to the background. A
 * script running inside a web page reports that page's URL, so the URL check
 * alone keeps every website out.
 */
function isTrustedSender(sender) {
  if (!sender || sender.id !== api.runtime.id) return false;
  const base = api.runtime.getURL("");
  return typeof sender.url === "string" && sender.url.startsWith(base);
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!isTrustedSender(sender) || !msg || typeof msg !== "object") return false;
  const handler = Object.hasOwn(handlers, msg.type) ? handlers[msg.type] : null;
  if (!handler) return false;
  const reply = handler(msg).catch(toErrorResult);
  // The `browser` namespace (Firefox, and recent Chromium which now exposes
  // it too) answers with the promise a listener returns; the `chrome`
  // namespace of older Chrome only through sendResponse + `return true`.
  if (api === globalThis.browser) return reply;
  reply.then(sendResponse);
  return true;
});
