// Pure helpers shared by the background script and the popup.
// Nothing here touches browser APIs, so it is unit-tested with `node --test`.

export const HOST_NAME = "com.bigcommunity.ashypass";
export const REQUEST_TIMEOUT_MS = 30_000;
export const SEARCH_DEBOUNCE_MS = 200;
export const MAX_QUERY_LENGTH = 256;
export const GENERATE_KINDS = Object.freeze(["password", "passphrase", "pin"]);
export const COPY_FIELDS = Object.freeze(["username", "password", "totp"]);
export const FAVICON_BATCH_SIZE = 40;
export const LIST_CHUNK_SIZE = 100;
export const TYPE_FILTERS = Object.freeze(["all", "totp", "favorites"]);
/** Folder filter value for "No folder" (cannot collide with a real name: it has a NUL). */
export const NO_FOLDER = "\u0000none";
export const INLINE_SCRIPT_ID = "ashypass-inline";
export const INLINE_MATCHES = Object.freeze(["http://*/*", "https://*/*"]);
export const INLINE_MENU_PATH = "/inline/menu.html";
export const INLINE_TOKEN_TTL_MS = 5 * 60_000;
/** Client-side length limits for `add` (the host may enforce its own). */
export const FIELD_LIMITS = Object.freeze({ title: 512, username: 512, password: 4096, url: 2048, category: 256, notes: 65536 });

/** Error carrying a protocol/extension error code (see PROTOCOL.md). */
export class ExtError extends Error {
  constructor(code, message, extra = {}) {
    super(message || code);
    this.name = "ExtError";
    this.code = code;
    if (Number.isInteger(extra.attemptsLeft) && extra.attemptsLeft >= 0) this.attemptsLeft = extra.attemptsLeft;
  }
}

/** Serialisable error shape sent back to the popup. */
export function toErrorResult(err) {
  if (err instanceof ExtError) {
    const result = { ok: false, code: err.code, error: err.message };
    if (err.attemptsLeft !== undefined) result.attempts_left = err.attemptsLeft;
    return result;
  }
  return { ok: false, code: "internal", error: String(err?.message ?? err) };
}

function parseUrl(url) {
  if (typeof url !== "string" || url === "") return null;
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** Only ordinary web pages can be matched and filled. */
export function isFillableUrl(url) {
  const u = parseUrl(url);
  return u !== null && (u.protocol === "http:" || u.protocol === "https:") && u.hostname !== "";
}

/** Origin of an http(s) page, or null for anything else. */
export function pageOriginOf(url) {
  return isFillableUrl(url) ? new URL(url).origin : null;
}

/** Host shown in the popup header ("www." dropped), or "" when not a web page. */
export function hostForDisplay(url) {
  if (!isFillableUrl(url)) return "";
  const host = new URL(url).hostname;
  return host.startsWith("www.") && host.length > 4 ? host.slice(4) : host;
}

/**
 * Maps the text of a native-port disconnect to an error code.
 * Chrome: "Specified native messaging host not found." /
 *         "Access to the specified native messaging host is forbidden."
 * Firefox: "No such native application com.bigcommunity.ashypass" /
 *          "Attempt to postMessage on disconnected port".
 */
export function classifyDisconnect(message) {
  const text = String(message ?? "").toLowerCase();
  if (
    text.includes("not found") ||
    text.includes("no such native application") ||
    text.includes("forbidden") ||
    text.includes("not allowed")
  ) {
    return "not_installed";
  }
  return "disconnected";
}

/** Turns a `status` reply into one popup state. */
export function stateFromStatus(reply) {
  if (!reply || reply.enabled === false) return "disabled";
  if (reply.has_vault === false) return "no_vault";
  return reply.unlocked ? "unlocked" : "locked";
}

/** Error codes that change the popup state instead of being shown as an error. */
export const STATE_CODES = Object.freeze({
  not_installed: "not_installed",
  disabled: "disabled",
  no_vault: "no_vault",
  locked: "locked",
});

/** Keeps only the documented Summary fields, with safe types. */
export function sanitizeSummary(entry) {
  const e = entry && typeof entry === "object" ? entry : {};
  const id = typeof e.id === "string" || typeof e.id === "number" ? e.id : null;
  return {
    id,
    title: typeof e.title === "string" ? e.title : "",
    username: typeof e.username === "string" ? e.username : "",
    url: typeof e.url === "string" ? e.url : "",
    category: typeof e.category === "string" ? e.category : "",
    has_totp: e.has_totp === true,
    favorite: e.favorite === true,
  };
}

export function sanitizeEntries(list) {
  if (!Array.isArray(list)) return [];
  return list.map(sanitizeSummary).filter((e) => e.id !== null);
}

export function isValidId(id) {
  return (typeof id === "string" && id !== "" && id.length <= 256) || Number.isSafeInteger(id);
}

/** Sum of the per-frame results of scripting.executeScript. */
export function countFilled(results) {
  if (!Array.isArray(results)) return 0;
  let total = 0;
  for (const r of results) {
    if (r && Number.isInteger(r.result) && r.result > 0) total += r.result;
  }
  return total;
}

/**
 * Tracks requests in flight on one native port: assigns incrementing `rid`s,
 * resolves or rejects them when the reply with the same `rid` arrives, and
 * times them out.
 */
export class RequestTracker {
  constructor({
    timeoutMs = REQUEST_TIMEOUT_MS,
    // Wrapped: browsers throw "Illegal invocation" when setTimeout is called
    // as a method of another object (this.setTimer(...)).
    setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
    clearTimer = (id) => globalThis.clearTimeout(id),
  } = {}) {
    this.timeoutMs = timeoutMs;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.nextRid = 1;
    this.pending = new Map();
  }

  get size() {
    return this.pending.size;
  }

  /** Registers a request; returns the message to post and its promise. */
  create(cmd, fields = {}) {
    const rid = this.nextRid;
    this.nextRid = rid >= Number.MAX_SAFE_INTEGER ? 1 : rid + 1;
    const message = { ...fields, cmd, rid };
    const promise = new Promise((resolve, reject) => {
      const timer = this.setTimer(() => {
        if (this.pending.delete(rid)) {
          reject(new ExtError("timeout", "Ashy Pass did not answer in time."));
        }
      }, this.timeoutMs);
      this.pending.set(rid, { resolve, reject, timer });
    });
    return { rid, message, promise };
  }

  /** Handles one reply from the host. Returns false for unknown `rid`s. */
  settle(reply) {
    if (!reply || typeof reply !== "object") return false;
    const slot = this.pending.get(reply.rid);
    if (!slot) return false;
    this.pending.delete(reply.rid);
    this.clearTimer(slot.timer);
    if (reply.ok === true) {
      slot.resolve(reply);
    } else {
      const code = typeof reply.code === "string" && reply.code ? reply.code : "internal";
      const text = typeof reply.error === "string" ? reply.error : "";
      slot.reject(new ExtError(code, text, { attemptsLeft: reply.attempts_left }));
    }
    return true;
  }

  /** Rejects one request (e.g. postMessage threw). */
  fail(rid, error) {
    const slot = this.pending.get(rid);
    if (!slot) return false;
    this.pending.delete(rid);
    this.clearTimer(slot.timer);
    slot.reject(error);
    return true;
  }

  /** Rejects every request in flight (the port closed). */
  failAll(error) {
    const slots = [...this.pending.values()];
    this.pending.clear();
    for (const slot of slots) {
      this.clearTimer(slot.timer);
      slot.reject(error);
    }
    return slots.length;
  }
}

/** Trailing-edge debounce. */
export function debounce(
  fn,
  waitMs,
  { setTimer = (f, ms) => globalThis.setTimeout(f, ms), clearTimer = (id) => globalThis.clearTimeout(id) } = {},
) {
  let timer = null;
  const debounced = (...args) => {
    if (timer !== null) clearTimer(timer);
    timer = setTimer(() => {
      timer = null;
      fn(...args);
    }, waitMs);
  };
  debounced.cancel = () => {
    if (timer !== null) clearTimer(timer);
    timer = null;
  };
  return debounced;
}

/** Bullet mask for the generated password (roughly its length, 8 to 64). */
export function maskSecret(value) {
  return "•".repeat(Math.min(Math.max(String(value ?? "").length, 8), 64));
}

// ── Vault data ──────────────────────────────────────────────────────────────

/** Folder names from a `folders` reply: unique, non-empty strings, sorted. */
export function sanitizeFolders(list) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  for (const name of list) {
    if (typeof name !== "string") continue;
    const trimmed = name.trim();
    if (trimmed === "" || trimmed.length > FIELD_LIMITS.category) continue;
    seen.add(trimmed);
  }
  return [...seen].sort((a, b) => a.localeCompare(b));
}

/** Client-side Folder and Type filters for the entry list. */
export function filterEntries(entries, { folder = "", type = "all" } = {}) {
  if (!Array.isArray(entries)) return [];
  return entries.filter((e) => {
    if (folder === NO_FOLDER && e.category !== "") return false;
    if (folder !== "" && folder !== NO_FOLDER && e.category !== folder) return false;
    if (type === "totp" && !e.has_totp) return false;
    if (type === "favorites" && !e.favorite) return false;
    return true;
  });
}

/** True when a Folder or Type filter is set. */
export function hasActiveFilter({ folder = "", type = "all" } = {}) {
  return folder !== "" || (type !== "all" && TYPE_FILTERS.includes(type));
}

/**
 * Host whose favicon is asked for: the hostname of an http(s) URL. Entries
 * sometimes store a bare domain ("example.com"), which is read as https.
 */
export function faviconHost(url) {
  if (typeof url !== "string") return "";
  const text = url.trim();
  if (text === "") return "";
  let u = parseUrl(text);
  if (u === null && !/^[a-z][a-z0-9+.-]*:/i.test(text)) u = parseUrl(`https://${text}`);
  if (u === null || (u.protocol !== "http:" && u.protocol !== "https:")) return "";
  return u.hostname.toLowerCase();
}

/** URL that "Open website" may open: http(s) only, bare domains read as https. */
export function openableUrl(url) {
  if (typeof url !== "string") return "";
  const text = url.trim();
  if (isFillableUrl(text)) return new URL(text).href;
  if (text !== "" && !/^[a-z][a-z0-9+.-]*:/i.test(text) && isFillableUrl(`https://${text}`)) {
    return new URL(`https://${text}`).href;
  }
  return "";
}

const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$|^\[[0-9a-f:.]+\]$/;

/** Hostnames that may be sent in a `favicons` request (deduplicated, at most one batch). */
export function sanitizeHosts(list) {
  if (!Array.isArray(list)) return [];
  const out = new Set();
  for (const h of list) {
    if (typeof h !== "string" || h.length > 253) continue;
    const host = h.toLowerCase();
    if (HOST_RE.test(host)) out.add(host);
    if (out.size >= FAVICON_BATCH_SIZE) break;
  }
  return [...out];
}

const MAX_ICON_LENGTH = 256 * 1024;
const ICON_RE = /^data:image\/(png|x-icon|vnd\.microsoft\.icon|gif|jpeg|webp|svg\+xml|bmp);base64,[A-Za-z0-9+/]+=*$/;

/** Keeps only data:image URLs for the hosts that were asked for. */
export function sanitizeIcons(icons, hosts) {
  const out = {};
  if (!icons || typeof icons !== "object") return out;
  for (const host of hosts) {
    const value = Object.hasOwn(icons, host) ? icons[host] : null;
    if (typeof value === "string" && value.length <= MAX_ICON_LENGTH && ICON_RE.test(value)) out[host] = value;
  }
  return out;
}

/**
 * Asks for favicons in batches of at most FAVICON_BATCH_SIZE hosts, and
 * remembers every answer (also "no icon") for the life of the page.
 * `fetchBatch(hosts)` resolves to `{host: dataUrl}`.
 */
export class FaviconBatcher {
  constructor(
    fetchBatch,
    {
      batchSize = FAVICON_BATCH_SIZE,
      delayMs = 25,
      setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
    } = {},
  ) {
    this.fetchBatch = fetchBatch;
    this.batchSize = batchSize;
    this.delayMs = delayMs;
    this.setTimer = setTimer;
    this.cache = new Map(); // host -> Promise<string|null>
    this.queue = new Map(); // host -> resolve
    this.scheduled = false;
  }

  /** Promise of the icon's data URL, or null when the app has none. */
  get(host) {
    if (typeof host !== "string" || host === "") return Promise.resolve(null);
    const cached = this.cache.get(host);
    if (cached) return cached;
    let resolve;
    const promise = new Promise((r) => {
      resolve = r;
    });
    this.cache.set(host, promise);
    this.queue.set(host, resolve);
    if (!this.scheduled) {
      this.scheduled = true;
      this.setTimer(() => this.flush(), this.delayMs);
    }
    return promise;
  }

  async flush() {
    this.scheduled = false;
    const entries = [...this.queue];
    this.queue.clear();
    const batches = [];
    for (let i = 0; i < entries.length; i += this.batchSize) batches.push(entries.slice(i, i + this.batchSize));
    await Promise.all(
      batches.map(async (batch) => {
        let icons = {};
        try {
          icons = (await this.fetchBatch(batch.map(([host]) => host))) ?? {};
        } catch {
          icons = {};
        }
        for (const [host, resolve] of batch) {
          resolve(typeof icons[host] === "string" ? icons[host] : null);
        }
      }),
    );
  }
}

/** Letter and colour for an entry without favicon. */
const AVATAR_COLORS = ["#3584e4", "#2190a4", "#3a944a", "#c88800", "#ed5b00", "#e62d42", "#d56199", "#9141ac", "#6f8396"];

export function avatarFor(title) {
  const text = String(title ?? "").trim();
  const letter = text === "" ? "?" : Array.from(text)[0].toLocaleUpperCase();
  let hash = 0;
  for (const ch of text) hash = (hash * 31 + ch.codePointAt(0)) >>> 0;
  return { letter, color: AVATAR_COLORS[hash % AVATAR_COLORS.length] };
}

/** Fields for `add` and `update`, trimmed (notes keep their spacing) and
 * limited. Throws ExtError("invalid") without title or password. */
export function sanitizeNewEntry(msg) {
  const str = (v, max, trim = true) => {
    if (typeof v !== "string") return "";
    const value = trim ? v.trim() : v;
    return value.length > max ? null : value;
  };
  const title = str(msg?.title, FIELD_LIMITS.title);
  const username = str(msg?.username, FIELD_LIMITS.username);
  const password = str(msg?.password, FIELD_LIMITS.password, false);
  const url = str(msg?.url, FIELD_LIMITS.url);
  const category = str(msg?.category, FIELD_LIMITS.category);
  const notes = str(msg?.notes, FIELD_LIMITS.notes, false);
  if ([title, username, password, url, category, notes].includes(null)) throw new ExtError("invalid", "A field is too long.");
  if (title === "") throw new ExtError("invalid", "Missing name.");
  if (password === "") throw new ExtError("invalid", "Missing password.");
  const fields = { title, password };
  if (username !== "") fields.username = username;
  if (url !== "") fields.url = url;
  if (category !== "") fields.category = category;
  if (notes.trim() !== "") fields.notes = notes;
  return fields;
}

// ── Generator ───────────────────────────────────────────────────────────────

export const GENERATOR_DEFAULTS = Object.freeze({
  kind: "password",
  password: Object.freeze({ length: 20, uppercase: true, lowercase: true, digits: true, symbols: true, avoidAmbiguous: false }),
  passphrase: Object.freeze({ words: 5, separator: "-", capitalize: true, number: false }),
  pin: Object.freeze({ length: 6 }),
});

export const GENERATOR_RANGES = Object.freeze({
  passwordLength: [8, 64],
  words: [3, 12],
  pinLength: [4, 12],
});

const clampInt = (v, [min, max], fallback) => {
  const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v;
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
};
const bool = (v, fallback) => (typeof v === "boolean" ? v : fallback);

/** Separator for passphrases: at most 3 characters, no control characters. */
export function cleanSeparator(value) {
  if (typeof value !== "string") return GENERATOR_DEFAULTS.passphrase.separator;
  // eslint-disable-next-line no-control-regex
  return Array.from(value.replace(/[\u0000-\u001f\u007f]/g, "")).slice(0, 3).join("");
}

/** Full, valid generator options from whatever was stored (or sent). */
export function normalizeGeneratorOptions(raw) {
  const o = raw && typeof raw === "object" ? raw : {};
  const d = GENERATOR_DEFAULTS;
  const pw = o.password && typeof o.password === "object" ? o.password : {};
  const pp = o.passphrase && typeof o.passphrase === "object" ? o.passphrase : {};
  const pin = o.pin && typeof o.pin === "object" ? o.pin : {};
  const password = {
    length: clampInt(pw.length, GENERATOR_RANGES.passwordLength, d.password.length),
    uppercase: bool(pw.uppercase, d.password.uppercase),
    lowercase: bool(pw.lowercase, d.password.lowercase),
    digits: bool(pw.digits, d.password.digits),
    symbols: bool(pw.symbols, d.password.symbols),
    avoidAmbiguous: bool(pw.avoidAmbiguous, d.password.avoidAmbiguous),
  };
  // At least one character class.
  if (!password.uppercase && !password.lowercase && !password.digits && !password.symbols) password.lowercase = true;
  return {
    kind: GENERATE_KINDS.includes(o.kind) ? o.kind : d.kind,
    password,
    passphrase: {
      words: clampInt(pp.words, GENERATOR_RANGES.words, d.passphrase.words),
      separator: typeof pp.separator === "string" ? cleanSeparator(pp.separator) : d.passphrase.separator,
      capitalize: bool(pp.capitalize, d.passphrase.capitalize),
      number: bool(pp.number, d.passphrase.number),
    },
    pin: { length: clampInt(pin.length, GENERATOR_RANGES.pinLength, d.pin.length) },
  };
}

/** The `generate` request fields (PROTOCOL.md) for the selected kind. */
export function generatorRequest(raw) {
  const o = normalizeGeneratorOptions(raw);
  switch (o.kind) {
    case "passphrase":
      return {
        kind: "passphrase",
        words: o.passphrase.words,
        separator: o.passphrase.separator,
        capitalize: o.passphrase.capitalize,
        number: o.passphrase.number,
      };
    case "pin":
      return { kind: "pin", length: o.pin.length };
    default:
      return {
        kind: "password",
        length: o.password.length,
        uppercase: o.password.uppercase,
        lowercase: o.password.lowercase,
        digits: o.password.digits,
        symbols: o.password.symbols,
        avoid_ambiguous: o.password.avoidAmbiguous,
      };
  }
}

// ── TOTP countdown ──────────────────────────────────────────────────────────

/** Fraction (0–1) of the period still left, for the countdown ring. */
export function totpFraction(remaining, period) {
  if (!Number.isFinite(remaining) || !Number.isFinite(period) || period <= 0) return 0;
  return Math.min(1, Math.max(0, remaining / period));
}

// ── Message senders ─────────────────────────────────────────────────────────

const EXTENSION_SCHEMES = new Set(["chrome-extension:", "moz-extension:", "extension:"]);

/**
 * Who sent a runtime message:
 * - "page": one of our extension pages (the popup);
 * - "menu": our inline suggestions page (inline/menu.html), framed in a tab;
 * - "content": our content script, running in an http(s) page of a tab;
 * - null: anything else (other extensions, unknown senders).
 * Chrome may load the menu from a per-session "dynamic" URL, so the menu is
 * also recognised by scheme and path; `sender.id` is checked first.
 */
export function senderKind(sender, extensionId, baseUrl) {
  if (!sender || typeof sender !== "object" || sender.id !== extensionId) return null;
  const url = typeof sender.url === "string" ? sender.url : "";
  const parsed = parseUrl(url);
  if (parsed === null) return null;
  if (url.startsWith(baseUrl)) return parsed.pathname === INLINE_MENU_PATH ? "menu" : "page";
  if (EXTENSION_SCHEMES.has(parsed.protocol)) return parsed.pathname === INLINE_MENU_PATH ? "menu" : null;
  if (isFillableUrl(url) && sender.tab && Number.isInteger(sender.tab.id)) return "content";
  return null;
}

/** Message types each sender kind may use. Content scripts get no data. */
export const ALLOWED_TYPES = Object.freeze({
  content: Object.freeze(new Set(["inlineOpen"])),
  menu: Object.freeze(new Set(["inlineMenuState", "inlineFill", "inlineOpenPopup", "favicons"])),
});

// ── Inline menu tokens ──────────────────────────────────────────────────────

function randomToken() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export const TOKEN_RE = /^[0-9a-f]{32}$/;

/**
 * Opening tokens for the inline suggestions menu. The content script gets one
 * for {tabId, frameId, origin}; the menu frame hands it back to read the
 * suggestions (which binds the token to that menu frame) and to fill once.
 */
export class InlineTokens {
  constructor({ ttlMs = INLINE_TOKEN_TTL_MS, now = () => Date.now(), random = randomToken, max = 64 } = {}) {
    this.ttlMs = ttlMs;
    this.now = now;
    this.random = random;
    this.max = max;
    this.tokens = new Map();
  }

  get size() {
    return this.tokens.size;
  }

  prune() {
    const t = this.now();
    for (const [token, rec] of this.tokens) if (rec.expires <= t) this.tokens.delete(token);
  }

  issue({ tabId, frameId, origin }) {
    this.prune();
    // A frame has one menu at a time: drop its older tokens.
    for (const [token, rec] of this.tokens) {
      if (rec.tabId === tabId && rec.frameId === frameId) this.tokens.delete(token);
    }
    while (this.tokens.size >= this.max) this.tokens.delete(this.tokens.keys().next().value);
    const token = this.random();
    this.tokens.set(token, { tabId, frameId, origin, expires: this.now() + this.ttlMs, menuFrameId: undefined });
    return token;
  }

  /** Looks a token up for the menu frame that uses it; binds it on first use. */
  claim(token, { tabId, menuFrameId }) {
    if (typeof token !== "string" || !TOKEN_RE.test(token)) return null;
    const rec = this.tokens.get(token);
    if (!rec) return null;
    if (rec.expires <= this.now()) {
      this.tokens.delete(token);
      return null;
    }
    if (rec.tabId !== tabId) return null;
    const frame = menuFrameId ?? -1;
    if (rec.menuFrameId === undefined) rec.menuFrameId = frame;
    else if (rec.menuFrameId !== frame) return null;
    return { tabId: rec.tabId, frameId: rec.frameId, origin: rec.origin };
  }

  /** Like claim, but the token can never be used again. */
  consume(token, who) {
    const rec = this.claim(token, who);
    if (rec) this.tokens.delete(token);
    return rec;
  }

  revokeTab(tabId) {
    for (const [token, rec] of this.tokens) if (rec.tabId === tabId) this.tokens.delete(token);
  }
}
