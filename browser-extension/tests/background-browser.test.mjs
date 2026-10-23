// With the `browser` namespace (Firefox, and recent Chromium such as Brave,
// which exposes it too) a runtime.onMessage listener must RETURN the promise:
// sendResponse + `return true` does not answer there.
import { test, before } from "node:test";
import assert from "node:assert/strict";

const EXT_ID = "ashypass@big-comm.github.io";
const BASE = "moz-extension://5d1c4c5e-0000-4000-8000-000000000000/";
const POPUP = { id: EXT_ID, url: `${BASE}popup/popup.html` };

function event() {
  const listeners = [];
  return { listeners, addListener: (fn) => listeners.push(fn), fire: (...a) => listeners.map((fn) => fn(...a)) };
}

const onMessage = event();
const browser = {
  runtime: {
    id: EXT_ID,
    getURL: (p) => BASE + p,
    onMessage,
    connectNative() {
      const port = { onMessage: event(), onDisconnect: event() };
      port.postMessage = (msg) => {
        const { rid } = msg; // the background wipes the message right after posting
        queueMicrotask(() => port.onMessage.fire({ rid, ok: true }));
      };
      return port;
    },
  },
  tabs: { get: async () => ({}), onRemoved: event() },
  scripting: { getRegisteredContentScripts: async () => [] },
  permissions: { contains: async () => false, onAdded: event(), onRemoved: event() },
};

before(async () => {
  globalThis.browser = browser;
  globalThis.chrome = { runtime: { id: "should-not-be-used" } };
  await import("../src/background.js");
});

test("the listener returns a promise and never calls sendResponse", async () => {
  let called = false;
  const [result] = onMessage.fire({ type: "lock" }, POPUP, () => {
    called = true;
  });
  assert.ok(result instanceof Promise, "must return the promise");
  assert.deepEqual(await result, { ok: true });
  assert.equal(called, false);
});

test("ignored messages return false (no promise)", () => {
  assert.deepEqual(onMessage.fire({ type: "nope" }, POPUP, () => {}), [false]);
  const page = { id: EXT_ID, url: "https://evil.example/", tab: { id: 1 } };
  assert.deepEqual(onMessage.fire({ type: "lock" }, page, () => {}), [false]);
});

test("Firefox menu frames are recognised by their moz-extension URL", async () => {
  const menu = { id: EXT_ID, url: `${BASE}inline/menu.html`, tab: { id: 1 }, frameId: 2 };
  const [result] = onMessage.fire({ type: "inlineMenuState", token: "f".repeat(32) }, menu, () => {});
  assert.equal((await result).code, "bad_token");
});
