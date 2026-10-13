import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ExtError,
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
    { id: "a1", title: "GitHub", username: "me", url: "https://github.com", category: "login", has_totp: true },
    { id: 7, title: "", username: "", url: "", category: "", has_totp: false },
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
