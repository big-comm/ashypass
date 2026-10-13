// Drives background.js through a fake `chrome` API and a scripted native host.
import { test, before } from "node:test";
import assert from "node:assert/strict";

const EXT_ID = "opelfkfheadglgamfephkfejfpcnlbck";
const BASE = `chrome-extension://${EXT_ID}/`;
const POPUP = { id: EXT_ID, url: `${BASE}popup/popup.html` };

function event() {
  const listeners = [];
  return {
    listeners,
    addListener: (fn) => listeners.push(fn),
    fire: (...args) => listeners.map((fn) => fn(...args)),
  };
}

const world = {
  hostInstalled: true,
  connects: 0,
  posted: [],
  port: null,
  respond: null, // (msg) => reply object or undefined (no reply)
  tabs: new Map(),
  scripts: [],
  scriptResults: [{ frameId: 0, result: 2 }],
};

function makePort() {
  const port = { onMessage: event(), onDisconnect: event(), disconnected: false };
  port.postMessage = (msg) => {
    if (port.disconnected) throw new Error("Attempt to postMessage on disconnected port");
    const copy = structuredClone(msg);
    world.posted.push(copy);
    queueMicrotask(() => {
      const reply = world.respond?.(copy);
      if (reply) port.onMessage.fire({ rid: copy.rid, ...reply });
    });
  };
  return port;
}

const onMessage = event();
const chrome = {
  runtime: {
    id: EXT_ID,
    lastError: undefined,
    getURL: (p) => BASE + p,
    onMessage,
    connectNative(name) {
      assert.equal(name, "com.bigcommunity.ashypass");
      world.connects += 1;
      const port = makePort();
      world.port = port;
      if (!world.hostInstalled) {
        setTimeout(() => {
          port.disconnected = true;
          chrome.runtime.lastError = { message: "Specified native messaging host not found." };
          port.onDisconnect.fire(port);
          chrome.runtime.lastError = undefined;
        }, 0);
      }
      return port;
    },
  },
  tabs: {
    get: async (id) => {
      if (!world.tabs.has(id)) throw new Error("No tab with id");
      return { id, url: world.tabs.get(id) };
    },
  },
  scripting: {
    executeScript: async (details) => {
      world.scripts.push(details);
      return world.scriptResults;
    },
  },
};

function send(msg, sender = POPUP) {
  return new Promise((resolve) => {
    const results = onMessage.fire(msg, sender, resolve);
    if (results[0] !== true) resolve(undefined);
  });
}

before(async () => {
  globalThis.chrome = chrome;
  await import("../src/background.js");
});

test("status maps a missing host to not_installed and reconnects next time", async () => {
  world.hostInstalled = false;
  const reply = await send({ type: "status" });
  assert.deepEqual(reply, { ok: true, state: "not_installed" });

  world.hostInstalled = true;
  world.respond = (m) => (m.cmd === "status" ? { ok: true, enabled: true, has_vault: true, unlocked: false } : null);
  const before = world.connects;
  assert.deepEqual(await send({ type: "status" }), { ok: true, state: "locked" });
  assert.equal(world.connects, before + 1);
  // The same port is reused.
  await send({ type: "status" });
  assert.equal(world.connects, before + 1);
});

test("status error codes become states", async () => {
  world.respond = () => ({ ok: false, code: "disabled", error: "Browser integration is off" });
  assert.deepEqual(await send({ type: "status" }), { ok: true, state: "disabled" });
});

test("rids are unique and replies are matched by rid", async () => {
  world.posted = [];
  const delayed = [];
  world.respond = (m) => {
    delayed.push(m);
    return null;
  };
  const p1 = send({ type: "search", query: "git" });
  const p2 = send({ type: "search", query: "mail" });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(delayed.length, 2);
  assert.notEqual(delayed[0].rid, delayed[1].rid);
  // Answer in reverse order.
  world.port.onMessage.fire({ ok: true, rid: delayed[1].rid, entries: [{ id: "m", title: "Mail" }] });
  world.port.onMessage.fire({ ok: true, rid: delayed[0].rid, entries: [{ id: "g", title: "Git" }] });
  assert.equal((await p1).entries[0].id, "g");
  assert.equal((await p2).entries[0].id, "m");
});

test("a disconnect rejects every pending request", async () => {
  world.respond = () => null;
  const p1 = send({ type: "lock" });
  const p2 = send({ type: "search", query: "x" });
  await new Promise((r) => setTimeout(r, 0));
  const port = world.port;
  port.disconnected = true;
  chrome.runtime.lastError = { message: "Native host has exited." };
  port.onDisconnect.fire(port);
  chrome.runtime.lastError = undefined;
  assert.deepEqual(await p1, { ok: false, code: "disconnected", error: "Native host has exited." });
  assert.equal((await p2).code, "disconnected");
});

test("unlock forwards the password once and reports bad_password", async () => {
  world.posted = [];
  world.respond = (m) => (m.cmd === "unlock" ? { ok: false, code: "bad_password", error: "Wrong master password" } : null);
  const reply = await send({ type: "unlock", password: "hunter2" });
  assert.equal(reply.code, "bad_password");
  assert.equal(world.posted.length, 1);
  assert.equal(world.posted[0].cmd, "unlock");
  assert.equal(world.posted[0].password, "hunter2");
});

test("match uses the tab URL and returns the display host", async () => {
  world.tabs.set(5, "https://www.github.com/login?return_to=x");
  world.posted = [];
  world.respond = (m) => ({ ok: true, entries: [{ id: "1", title: "GitHub", username: "me", url: m.url, has_totp: true }] });
  const reply = await send({ type: "match", tabId: 5 });
  assert.equal(world.posted[0].cmd, "match_url");
  assert.equal(world.posted[0].url, "https://www.github.com/login?return_to=x");
  assert.equal(reply.host, "github.com");
  assert.equal(reply.fillable, true);
  assert.equal(reply.entries[0].has_totp, true);
});

test("match on a non-web page does not ask the host", async () => {
  world.tabs.set(6, "chrome://settings");
  world.posted = [];
  const reply = await send({ type: "match", tabId: 6 });
  assert.deepEqual(reply, { ok: true, host: "", fillable: false, entries: [] });
  assert.equal(world.posted.length, 0);
});

test("fill asks the host with the tab URL and injects into same-origin frames only", async () => {
  world.tabs.set(7, "https://example.com/sign-in");
  world.posted = [];
  world.scripts = [];
  world.respond = (m) => (m.cmd === "fill" ? { ok: true, username: "alice", password: "pw" } : null);
  const reply = await send({ type: "fill", tabId: 7, id: "e1" });
  assert.deepEqual(reply, { ok: true, filled: 2 });
  assert.deepEqual(
    { cmd: world.posted[0].cmd, id: world.posted[0].id, url: world.posted[0].url },
    { cmd: "fill", id: "e1", url: "https://example.com/sign-in" },
  );
  const call = world.scripts[0];
  assert.deepEqual(call.target, { tabId: 7, allFrames: true });
  assert.equal(call.func.name, "fillCredentials");
  assert.deepEqual(call.args, ["alice", "pw", "https://example.com"]);
});

test("fill never calls get, refuses non-web pages and passes no_match through", async () => {
  world.tabs.set(8, "file:///home/me/page.html");
  world.posted = [];
  assert.equal((await send({ type: "fill", tabId: 8, id: "e1" })).code, "not_web_page");
  assert.equal(world.posted.length, 0);

  world.tabs.set(9, "https://evil.example/");
  world.respond = (m) => (m.cmd === "fill" ? { ok: false, code: "no_match", error: "Entry does not match" } : null);
  assert.equal((await send({ type: "fill", tabId: 9, id: "e1" })).code, "no_match");
  assert.ok(world.posted.every((m) => m.cmd !== "get"));
});

test("copy uses get for username/password and totp for codes", async () => {
  world.posted = [];
  world.respond = (m) => {
    if (m.cmd === "get") return { ok: true, entry: { id: m.id, username: "alice", password: "pw" } };
    if (m.cmd === "totp") return { ok: true, code: "123456", remaining: 20, period: 30 };
    return null;
  };
  assert.equal((await send({ type: "copy", id: "e1", field: "password" })).value, "pw");
  assert.equal((await send({ type: "copy", id: "e1", field: "username" })).value, "alice");
  assert.equal((await send({ type: "copy", id: "e1", field: "totp" })).value, "123456");
  assert.deepEqual(world.posted.map((m) => m.cmd), ["get", "get", "totp"]);
  assert.equal((await send({ type: "copy", id: "e1", field: "notes" })).code, "invalid");
});

test("generate validates the kind", async () => {
  world.posted = [];
  world.respond = (m) => ({ ok: true, password: `gen-${m.kind}` });
  assert.equal((await send({ type: "generate", kind: "pin" })).value, "gen-pin");
  assert.equal((await send({ type: "generate", kind: "evil" })).value, "gen-password");
});

test("messages from web pages or other extensions are ignored", async () => {
  world.posted = [];
  world.respond = () => ({ ok: true, entry: { password: "pw" } });
  const fromPage = { id: EXT_ID, url: "https://evil.example/", tab: { id: 1 } };
  const fromOther = { id: "someotherextension", url: "chrome-extension://someotherextension/x.html" };
  assert.equal(await send({ type: "copy", id: "e1", field: "password" }, fromPage), undefined);
  assert.equal(await send({ type: "copy", id: "e1", field: "password" }, fromOther), undefined);
  assert.equal(await send({ type: "nope" }), undefined);
  assert.equal(world.posted.length, 0);
});
