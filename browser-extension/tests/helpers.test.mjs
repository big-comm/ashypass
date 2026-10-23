import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ALLOWED_TYPES,
  ExtError,
  FaviconBatcher,
  InlineTokens,
  NO_FOLDER,
  avatarFor,
  cleanSeparator,
  faviconHost,
  filterEntries,
  generatorRequest,
  hasActiveFilter,
  normalizeGeneratorOptions,
  openableUrl,
  sanitizeFolders,
  sanitizeHosts,
  sanitizeIcons,
  sanitizeNewEntry,
  senderKind,
  totpFraction,
  RequestTracker,
  classifyDisconnect,
  countFilled,
  debounce,
  hostForDisplay,
  isFillableUrl,
  isValidId,
  maskSecret,
  pageOriginOf,
  sanitizeEntries,
  stateFromStatus,
  toErrorResult,
} from "../src/lib/helpers.js";

test("isFillableUrl accepts only http and https pages", () => {
  assert.equal(isFillableUrl("https://example.com/login"), true);
  assert.equal(isFillableUrl("http://localhost:8080/"), true);
  for (const url of [
    "chrome://extensions",
    "about:blank",
    "file:///etc/passwd",
    "moz-extension://x/popup.html",
    "data:text/html,hi",
    "javascript:alert(1)",
    "",
    undefined,
    "not a url",
  ]) {
    assert.equal(isFillableUrl(url), false, String(url));
  }
});

test("pageOriginOf returns the origin or null", () => {
  assert.equal(pageOriginOf("https://a.example.com:8443/x?y#z"), "https://a.example.com:8443");
  assert.equal(pageOriginOf("about:blank"), null);
});

test("hostForDisplay drops www. and returns empty for non-web pages", () => {
  assert.equal(hostForDisplay("https://www.github.com/login"), "github.com");
  assert.equal(hostForDisplay("https://accounts.google.com/"), "accounts.google.com");
  assert.equal(hostForDisplay("http://192.168.0.1:8080/"), "192.168.0.1");
  assert.equal(hostForDisplay("https://bücher.example/"), "xn--bcher-kva.example");
  assert.equal(hostForDisplay("chrome://newtab"), "");
});

test("classifyDisconnect maps missing hosts to not_installed", () => {
  assert.equal(classifyDisconnect("Specified native messaging host not found."), "not_installed");
  assert.equal(classifyDisconnect("Access to the specified native messaging host is forbidden."), "not_installed");
  assert.equal(classifyDisconnect("No such native application com.bigcommunity.ashypass"), "not_installed");
  assert.equal(classifyDisconnect("Native host has exited."), "disconnected");
  assert.equal(classifyDisconnect(""), "disconnected");
  assert.equal(classifyDisconnect(undefined), "disconnected");
});

test("stateFromStatus", () => {
  assert.equal(stateFromStatus({ ok: true, enabled: false, has_vault: true, unlocked: true }), "disabled");
  assert.equal(stateFromStatus({ ok: true, enabled: true, has_vault: false, unlocked: false }), "no_vault");
  assert.equal(stateFromStatus({ ok: true, enabled: true, has_vault: true, unlocked: false }), "locked");
  assert.equal(stateFromStatus({ ok: true, enabled: true, has_vault: true, unlocked: true }), "unlocked");
});

test("sanitizeEntries keeps only Summary fields and drops entries without id", () => {
  const out = sanitizeEntries([
    { id: "a1", title: "GitHub", username: "me", url: "https://github.com", category: "login", has_totp: true, password: "x" },
    { id: 7, title: 3 },
    { title: "no id" },
    null,
  ]);
  assert.deepEqual(out, [
    { id: "a1", title: "GitHub", username: "me", url: "https://github.com", category: "login", has_totp: true, favorite: false },
    { id: 7, title: "", username: "", url: "", category: "", has_totp: false, favorite: false },
  ]);
  assert.deepEqual(sanitizeEntries(undefined), []);
});

test("isValidId", () => {
  assert.equal(isValidId("abc"), true);
  assert.equal(isValidId(12), true);
  assert.equal(isValidId(""), false);
  assert.equal(isValidId(1.5), false);
  assert.equal(isValidId({}), false);
  assert.equal(isValidId("x".repeat(300)), false);
});

test("countFilled sums frame results", () => {
  assert.equal(countFilled([{ frameId: 0, result: 2 }, { frameId: 3, result: 0 }, { frameId: 4, result: 1 }]), 3);
  assert.equal(countFilled([{ frameId: 0, result: null }, { frameId: 1 }]), 0);
  assert.equal(countFilled(undefined), 0);
});

test("toErrorResult", () => {
  assert.deepEqual(toErrorResult(new ExtError("locked", "Vault is locked")), {
    ok: false,
    code: "locked",
    error: "Vault is locked",
  });
  assert.deepEqual(toErrorResult(new Error("x")), { ok: false, code: "internal", error: "x" });
});

test("maskSecret never reveals the value", () => {
  assert.equal(maskSecret("abc"), "••••••••");
  assert.equal(maskSecret("a".repeat(20)), "•".repeat(20));
  assert.equal(maskSecret("a".repeat(500)).length, 64);
});

// ── RequestTracker ──────────────────────────────────────────────────────────

function fakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    timers,
    setTimer(fn, ms) {
      const id = next++;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimer(id) {
      timers.delete(id);
    },
    fireAll() {
      for (const [id, t] of [...timers]) {
        timers.delete(id);
        t.fn();
      }
    },
  };
}

test("RequestTracker assigns incrementing rids and resolves by rid", async () => {
  const clock = fakeTimers();
  const tracker = new RequestTracker({ timeoutMs: 30_000, ...clock });
  const a = tracker.create("status");
  const b = tracker.create("search", { query: "git" });
  assert.equal(a.rid, 1);
  assert.equal(b.rid, 2);
  assert.deepEqual(b.message, { query: "git", cmd: "search", rid: 2 });
  assert.equal(tracker.size, 2);
  assert.equal([...clock.timers.values()][0].ms, 30_000);

  // Out-of-order replies.
  assert.equal(tracker.settle({ ok: true, rid: 2, entries: [] }), true);
  assert.equal(tracker.settle({ ok: true, rid: 1, unlocked: true }), true);
  assert.deepEqual(await b.promise, { ok: true, rid: 2, entries: [] });
  assert.equal((await a.promise).unlocked, true);
  assert.equal(tracker.size, 0);
  assert.equal(clock.timers.size, 0);
});

test("RequestTracker ignores unknown and duplicate rids", () => {
  const tracker = new RequestTracker(fakeTimers());
  const a = tracker.create("ping");
  assert.equal(tracker.settle({ ok: true, rid: 99 }), false);
  assert.equal(tracker.settle({ ok: true }), false);
  assert.equal(tracker.settle(null), false);
  assert.equal(tracker.settle({ ok: true, rid: a.rid }), true);
  assert.equal(tracker.settle({ ok: true, rid: a.rid }), false);
});

test("RequestTracker rejects host errors with their code", async () => {
  const tracker = new RequestTracker(fakeTimers());
  const a = tracker.create("unlock", { password: "x" });
  tracker.settle({ ok: false, rid: a.rid, code: "bad_password", error: "Wrong master password" });
  await assert.rejects(a.promise, (err) => err instanceof ExtError && err.code === "bad_password");
  const b = tracker.create("lock");
  tracker.settle({ ok: false, rid: b.rid });
  await assert.rejects(b.promise, (err) => err.code === "internal");
});

test("RequestTracker times out", async () => {
  const clock = fakeTimers();
  const tracker = new RequestTracker({ timeoutMs: 30_000, ...clock });
  const a = tracker.create("unlock");
  clock.fireAll();
  await assert.rejects(a.promise, (err) => err.code === "timeout");
  assert.equal(tracker.size, 0);
  assert.equal(tracker.settle({ ok: true, rid: a.rid }), false);
});

test("RequestTracker failAll rejects every pending request", async () => {
  const clock = fakeTimers();
  const tracker = new RequestTracker(clock);
  const reqs = [tracker.create("status"), tracker.create("search", { query: "a" }), tracker.create("lock")];
  const error = new ExtError("not_installed", "Specified native messaging host not found.");
  assert.equal(tracker.failAll(error), 3);
  for (const r of reqs) await assert.rejects(r.promise, (err) => err.code === "not_installed");
  assert.equal(tracker.size, 0);
  assert.equal(clock.timers.size, 0);
  assert.equal(tracker.failAll(error), 0);
});

test("RequestTracker fail rejects a single request", async () => {
  const tracker = new RequestTracker(fakeTimers());
  const a = tracker.create("status");
  const b = tracker.create("status");
  assert.equal(tracker.fail(a.rid, new ExtError("disconnected", "gone")), true);
  await assert.rejects(a.promise, (err) => err.code === "disconnected");
  assert.equal(tracker.size, 1);
  tracker.settle({ ok: true, rid: b.rid });
  await b.promise;
});

test("debounce runs only the last call", () => {
  const clock = fakeTimers();
  const calls = [];
  const d = debounce((q) => calls.push(q), 200, clock);
  d("g");
  d("gi");
  d("git");
  assert.equal(clock.timers.size, 1);
  assert.equal([...clock.timers.values()][0].ms, 200);
  clock.fireAll();
  assert.deepEqual(calls, ["git"]);
  d("x");
  d.cancel();
  clock.fireAll();
  assert.deepEqual(calls, ["git"]);
});

test("RequestTracker default timers work with a receiver-checking setTimeout", async () => {
  // Browsers reject setTimeout called with a foreign `this`; Node does not.
  const realSet = globalThis.setTimeout;
  const realClear = globalThis.clearTimeout;
  globalThis.setTimeout = function (fn, ms) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    return realSet(fn, ms);
  };
  globalThis.clearTimeout = function (id) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    return realClear(id);
  };
  try {
    const tracker = new RequestTracker({ timeoutMs: 1000 });
    const { rid, promise } = tracker.create("ping", {});
    tracker.settle({ rid, ok: true });
    assert.deepEqual(await promise, { rid, ok: true });
  } finally {
    globalThis.setTimeout = realSet;
    globalThis.clearTimeout = realClear;
  }
});

// ── Protocol 3 helpers ──────────────────────────────────────────────────────

test("sanitizeEntries keeps favorite as a boolean", () => {
  const [e] = sanitizeEntries([{ id: 1, favorite: "yes", has_totp: 1 }]);
  assert.equal(e.favorite, false);
  assert.equal(e.has_totp, false);
  assert.equal(sanitizeEntries([{ id: 1, favorite: true }])[0].favorite, true);
});

test("ExtError carries attempts_left into the error result", async () => {
  const tracker = new RequestTracker({ setTimer: () => 1, clearTimer: () => {} });
  const { rid, promise } = tracker.create("unlock_pin", { pin: "1" });
  tracker.settle({ rid, ok: false, code: "bad_pin", error: "Wrong PIN", attempts_left: 2 });
  const err = await promise.catch((e) => e);
  assert.deepEqual(toErrorResult(err), { ok: false, code: "bad_pin", error: "Wrong PIN", attempts_left: 2 });
  assert.equal(toErrorResult(new ExtError("bad_pin", "x", { attemptsLeft: "2" })).attempts_left, undefined);
});

const ENTRIES = [
  { id: 1, category: "Work", has_totp: true, favorite: false },
  { id: 2, category: "", has_totp: false, favorite: true },
  { id: 3, category: "Home", has_totp: true, favorite: true },
  { id: 4, category: "Work", has_totp: false, favorite: false },
];
const ids = (list) => list.map((e) => e.id);

test("filterEntries applies folder and type filters", () => {
  assert.deepEqual(ids(filterEntries(ENTRIES)), [1, 2, 3, 4]);
  assert.deepEqual(ids(filterEntries(ENTRIES, { folder: "Work" })), [1, 4]);
  assert.deepEqual(ids(filterEntries(ENTRIES, { folder: NO_FOLDER })), [2]);
  assert.deepEqual(ids(filterEntries(ENTRIES, { type: "totp" })), [1, 3]);
  assert.deepEqual(ids(filterEntries(ENTRIES, { type: "favorites" })), [2, 3]);
  assert.deepEqual(ids(filterEntries(ENTRIES, { folder: "Work", type: "totp" })), [1]);
  assert.deepEqual(filterEntries(null), []);
  assert.equal(hasActiveFilter({ folder: "", type: "all" }), false);
  assert.equal(hasActiveFilter({ folder: NO_FOLDER, type: "all" }), true);
  assert.equal(hasActiveFilter({ folder: "", type: "favorites" }), true);
});

test("sanitizeFolders dedupes, trims and sorts", () => {
  assert.deepEqual(sanitizeFolders(["b", " a ", "", null, "b", 3]), ["a", "b"]);
  assert.deepEqual(sanitizeFolders("x"), []);
});

test("faviconHost and openableUrl accept only http(s), bare domains as https", () => {
  assert.equal(faviconHost("https://WWW.GitHub.com/login"), "www.github.com");
  assert.equal(faviconHost("github.com"), "github.com");
  assert.equal(faviconHost("javascript:alert(1)"), "");
  assert.equal(faviconHost("file:///etc/passwd"), "");
  assert.equal(faviconHost(""), "");
  assert.equal(openableUrl("example.com/x"), "https://example.com/x");
  assert.equal(openableUrl("http://example.com/"), "http://example.com/");
  assert.equal(openableUrl("javascript:alert(1)"), "");
  assert.equal(openableUrl("data:text/html,hi"), "");
  assert.equal(openableUrl("chrome://settings"), "");
});

test("sanitizeHosts and sanitizeIcons", () => {
  const hosts = sanitizeHosts(["A.example", "a.example", "bad host", "x/y", 5, ...Array.from({ length: 50 }, (_, i) => `h${i}.example`)]);
  assert.equal(hosts.length, 40);
  assert.equal(hosts[0], "a.example");
  assert.ok(!hosts.includes("bad host"));
  const icons = sanitizeIcons(
    {
      "a.example": "data:image/png;base64,iVBORw0KGgo=",
      "b.example": "data:text/html;base64,PHNjcmlwdD4=",
      "c.example": "data:image/svg+xml;base64,PHN2Zz4=",
      "other.example": "data:image/png;base64,AAAA",
    },
    ["a.example", "b.example", "c.example"],
  );
  assert.deepEqual(Object.keys(icons), ["a.example", "c.example"]);
  assert.deepEqual(sanitizeIcons(null, ["a"]), {});
});

test("FaviconBatcher batches at most 40 hosts, dedupes and caches", async () => {
  const calls = [];
  const timers = [];
  const batcher = new FaviconBatcher(
    async (hosts) => {
      calls.push(hosts);
      return Object.fromEntries(hosts.filter((h) => h.startsWith("h1")).map((h) => [h, `icon:${h}`]));
    },
    { setTimer: (fn) => timers.push(fn) },
  );
  const hosts = Array.from({ length: 95 }, (_, i) => `h${i}.example`);
  const promises = [...hosts, "h1.example", "h2.example"].map((h) => batcher.get(h));
  assert.equal(timers.length, 1, "one flush scheduled");
  await timers[0]();
  assert.deepEqual(calls.map((c) => c.length), [40, 40, 15]);
  const results = await Promise.all(promises);
  assert.equal(results[1], "icon:h1.example");
  assert.equal(results[2], null);
  assert.equal(results[95], "icon:h1.example");
  // Cached: no new request.
  assert.equal(await batcher.get("h1.example"), "icon:h1.example");
  assert.equal(calls.length, 3);
  assert.equal(await batcher.get(""), null);
});

test("FaviconBatcher resolves null when a batch fails", async () => {
  const timers = [];
  const batcher = new FaviconBatcher(async () => {
    throw new Error("boom");
  }, { setTimer: (fn) => timers.push(fn) });
  const p = batcher.get("a.example");
  await timers[0]();
  assert.equal(await p, null);
});

test("avatarFor gives a letter and a stable colour", () => {
  assert.equal(avatarFor("github").letter, "G");
  assert.equal(avatarFor("").letter, "?");
  assert.equal(avatarFor("ação").color, avatarFor("ação").color);
});

test("normalizeGeneratorOptions clamps and keeps at least one class", () => {
  const o = normalizeGeneratorOptions({
    kind: "evil",
    password: { length: 500, uppercase: false, lowercase: false, digits: false, symbols: false },
    passphrase: { words: 1, separator: "\u0000ab\ncd" },
    pin: { length: "99" },
  });
  assert.equal(o.kind, "password");
  assert.equal(o.password.length, 64);
  assert.equal(o.password.lowercase, true);
  assert.equal(o.passphrase.words, 3);
  assert.equal(o.passphrase.separator, "abc");
  assert.equal(o.pin.length, 12);
  assert.deepEqual(normalizeGeneratorOptions(null).password.length, 20);
  assert.equal(normalizeGeneratorOptions({ password: { length: 3 } }).password.length, 8);
  assert.equal(cleanSeparator("🙂🙂🙂🙂"), "🙂🙂🙂");
});

test("generatorRequest maps each kind to the protocol fields", () => {
  assert.deepEqual(generatorRequest({ kind: "password", password: { length: 16, symbols: false, avoidAmbiguous: true } }), {
    kind: "password",
    length: 16,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: false,
    avoid_ambiguous: true,
  });
  assert.deepEqual(generatorRequest({ kind: "passphrase", passphrase: { words: 6, separator: ".", capitalize: false, number: true } }), {
    kind: "passphrase",
    words: 6,
    separator: ".",
    capitalize: false,
    number: true,
  });
  assert.deepEqual(generatorRequest({ kind: "pin", pin: { length: 2 } }), { kind: "pin", length: 4 });
  assert.equal(generatorRequest(undefined).kind, "password");
});

test("sanitizeNewEntry", () => {
  assert.deepEqual(sanitizeNewEntry({ title: " T ", password: " p ", username: " u ", url: "", category: "" }), {
    title: "T",
    password: " p ",
    username: "u",
  });
  assert.throws(() => sanitizeNewEntry({ title: "", password: "p" }), /Missing name/);
  assert.throws(() => sanitizeNewEntry({ title: "t", password: "" }), /Missing password/);
  assert.throws(() => sanitizeNewEntry({ title: "t".repeat(513), password: "p" }), /too long/);
});

test("totpFraction", () => {
  assert.equal(totpFraction(15, 30), 0.5);
  assert.equal(totpFraction(40, 30), 1);
  assert.equal(totpFraction(5, 0), 0);
  assert.equal(totpFraction(Number.NaN, 30), 0);
});

test("senderKind tells popup, menu frame, content script and strangers apart", () => {
  const id = "abc";
  const base = "chrome-extension://abc/";
  assert.equal(senderKind({ id, url: `${base}popup/popup.html` }, id, base), "page");
  assert.equal(senderKind({ id, url: `${base}inline/menu.html`, tab: { id: 1 } }, id, base), "menu");
  // Chrome's per-session dynamic URL for web-accessible resources.
  assert.equal(senderKind({ id, url: "chrome-extension://dynamic-uuid/inline/menu.html", tab: { id: 1 } }, id, base), "menu");
  assert.equal(senderKind({ id, url: "chrome-extension://dynamic-uuid/popup/popup.html" }, id, base), null);
  assert.equal(senderKind({ id, url: "https://site.example/", tab: { id: 1 } }, id, base), "content");
  assert.equal(senderKind({ id, url: "https://site.example/" }, id, base), null);
  assert.equal(senderKind({ id, url: "file:///x", tab: { id: 1 } }, id, base), null);
  assert.equal(senderKind({ id: "other", url: `${base}popup/popup.html` }, id, base), null);
  assert.equal(senderKind(null, id, base), null);
  assert.deepEqual([...ALLOWED_TYPES.content], ["inlineOpen"]);
  assert.ok(!ALLOWED_TYPES.menu.has("copy") && !ALLOWED_TYPES.menu.has("reveal"));
});

test("InlineTokens: bound to tab and menu frame, single use, expire", () => {
  let now = 1000;
  let n = 0;
  const tokens = new InlineTokens({ ttlMs: 100, now: () => now, random: () => (n++).toString(16).padStart(32, "0") });
  const t1 = tokens.issue({ tabId: 1, frameId: 3, origin: "https://a.example" });
  assert.equal(tokens.claim("not-a-token", { tabId: 1, menuFrameId: 5 }), null);
  assert.equal(tokens.claim(t1, { tabId: 2, menuFrameId: 5 }), null, "other tab");
  assert.deepEqual(tokens.claim(t1, { tabId: 1, menuFrameId: 5 }), { tabId: 1, frameId: 3, origin: "https://a.example" });
  assert.equal(tokens.claim(t1, { tabId: 1, menuFrameId: 6 }), null, "other menu frame");
  assert.ok(tokens.consume(t1, { tabId: 1, menuFrameId: 5 }));
  assert.equal(tokens.consume(t1, { tabId: 1, menuFrameId: 5 }), null, "single use");

  const t2 = tokens.issue({ tabId: 1, frameId: 3, origin: "https://a.example" });
  now += 100;
  assert.equal(tokens.claim(t2, { tabId: 1, menuFrameId: 5 }), null, "expired");
  assert.equal(tokens.size, 0);

  // A new token for the same frame replaces the old one; closing the tab drops them.
  const t3 = tokens.issue({ tabId: 1, frameId: 3, origin: "o" });
  const t4 = tokens.issue({ tabId: 1, frameId: 3, origin: "o" });
  assert.equal(tokens.claim(t3, { tabId: 1 }), null);
  tokens.issue({ tabId: 2, frameId: 0, origin: "o" });
  tokens.revokeTab(1);
  assert.equal(tokens.claim(t4, { tabId: 1 }), null);
  assert.equal(tokens.size, 1);
});

test("InlineTokens default random tokens are 128-bit hex", () => {
  const tokens = new InlineTokens();
  const a = tokens.issue({ tabId: 1, frameId: 0, origin: "o" });
  const b = tokens.issue({ tabId: 1, frameId: 1, origin: "o" });
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});
