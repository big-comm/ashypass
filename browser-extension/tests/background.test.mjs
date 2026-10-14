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
  permitted: false,
  registered: [],
  popupOpened: 0,
  hostInstalled: true,
  connects: 0,
  posted: [],
  port: null,
  respond: null, // (msg) => reply object or undefined (no reply)
  tabs: new Map(),
  scripts: [],
  scriptResults: [{ frameId: 0, result: 2 }],
  stored: {},
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
    onRemoved: event(),
  },
  scripting: {
    executeScript: async (details) => {
      world.scripts.push(details);
      return world.scriptResults;
    },
    getRegisteredContentScripts: async ({ ids }) => world.registered.filter((s) => ids.includes(s.id)),
    registerContentScripts: async (scripts) => {
      for (const s of scripts) {
        if (world.registered.some((r) => r.id === s.id)) throw new Error("Duplicate script ID");
        world.registered.push(s);
      }
    },
    unregisterContentScripts: async ({ ids }) => {
      world.registered = world.registered.filter((s) => !ids.includes(s.id));
    },
  },
  storage: {
    local: {
      get: async (key) => (key in world.stored ? { [key]: world.stored[key] } : {}),
      set: async (items) => {
        Object.assign(world.stored, items);
      },
      remove: async (key) => {
        delete world.stored[key];
      },
    },
  },
  permissions: {
    contains: async (p) => {
      assert.deepEqual(p, { origins: ["http://*/*", "https://*/*"] });
      return world.permitted;
    },
    remove: async () => {
      world.permitted = false;
      return true;
    },
    onAdded: event(),
    onRemoved: event(),
  },
  action: {
    openPopup: async () => {
      world.popupOpened += 1;
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
  assert.deepEqual(reply, { ok: true, state: "not_installed", pinAvailable: false });

  world.hostInstalled = true;
  world.respond = (m) =>
    m.cmd === "status" ? { ok: true, enabled: true, has_vault: true, unlocked: false, pin_available: true } : null;
  const before = world.connects;
  assert.deepEqual(await send({ type: "status" }), { ok: true, state: "locked", pinAvailable: true });
  assert.equal(world.connects, before + 1);
  // The same port is reused.
  await send({ type: "status" });
  assert.equal(world.connects, before + 1);
});

test("status error codes become states", async () => {
  world.respond = () => ({ ok: false, code: "disabled", error: "Browser integration is off" });
  assert.deepEqual(await send({ type: "status" }), { ok: true, state: "disabled", pinAvailable: false });
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
  assert.deepEqual(reply, { ok: true, host: "", origin: "", fillable: false, entries: [] });
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

// ── Protocol 3 commands ─────────────────────────────────────────────────────

test("onMessage with the chrome namespace answers through sendResponse and returns true", async () => {
  world.respond = () => ({ ok: true });
  let answered;
  const done = new Promise((resolve) => {
    answered = resolve;
  });
  const results = onMessage.fire({ type: "lock" }, POPUP, answered);
  assert.equal(results[0], true);
  assert.deepEqual(await done, { ok: true });
  // Unknown types and bad messages are not answered at all.
  assert.deepEqual(onMessage.fire({ type: "nope" }, POPUP, () => {}), [false]);
  assert.deepEqual(onMessage.fire(null, POPUP, () => {}), [false]);
});

test("unlockPin forwards the PIN and passes attempts_left through", async () => {
  world.posted = [];
  world.respond = (m) =>
    m.cmd === "unlock_pin" ? { ok: false, code: "bad_pin", error: "Wrong PIN", attempts_left: 3 } : null;
  const reply = await send({ type: "unlockPin", pin: "1234" });
  assert.deepEqual(reply, { ok: false, code: "bad_pin", error: "Wrong PIN", attempts_left: 3 });
  assert.deepEqual({ cmd: world.posted[0].cmd, pin: world.posted[0].pin }, { cmd: "unlock_pin", pin: "1234" });
  assert.equal((await send({ type: "unlockPin", pin: "" })).code, "bad_pin");
  assert.equal(world.posted.length, 1);
});

test("list, folders and toggleFavorite are sanitised", async () => {
  world.respond = (m) => {
    if (m.cmd === "list") return { ok: true, entries: [{ id: "1", title: "A", favorite: true, password: "leak" }, { title: "no id" }] };
    if (m.cmd === "folders") return { ok: true, folders: ["Work", "", 5, "Home", "Work"] };
    if (m.cmd === "toggle_favorite") return { ok: true, favorite: true };
    return null;
  };
  const list = await send({ type: "list" });
  assert.equal(list.entries.length, 1);
  assert.equal(list.entries[0].favorite, true);
  assert.equal(list.entries[0].password, undefined);
  assert.deepEqual((await send({ type: "folders" })).folders, ["Home", "Work"]);
  assert.deepEqual(await send({ type: "toggleFavorite", id: "1" }), { ok: true, favorite: true });
  assert.equal((await send({ type: "toggleFavorite" })).code, "invalid");
});

test("favicons sends at most 40 valid hosts and keeps only data:image answers", async () => {
  world.posted = [];
  world.respond = (m) => ({
    ok: true,
    icons: { "a0.example": "data:image/png;base64,AAAA", "a1.example": "javascript:alert(1)", "evil.example": "data:image/png;base64,AAAA" },
  });
  const hosts = ["bad host!", ...Array.from({ length: 60 }, (_, i) => `a${i}.example`)];
  const reply = await send({ type: "favicons", hosts });
  assert.equal(world.posted[0].hosts.length, 40);
  assert.ok(!world.posted[0].hosts.includes("bad host!"));
  assert.deepEqual(reply.icons, { "a0.example": "data:image/png;base64,AAAA" });
  world.posted = [];
  assert.deepEqual(await send({ type: "favicons", hosts: [] }), { ok: true, icons: {} });
  assert.equal(world.posted.length, 0);
});

test("reveal and totp use get and totp", async () => {
  world.respond = (m) => {
    if (m.cmd === "get") return { ok: true, entry: { id: m.id, password: "pw" } };
    if (m.cmd === "totp") return { ok: true, code: "123456", remaining: 12, period: 30 };
    return null;
  };
  assert.deepEqual(await send({ type: "reveal", id: "e1" }), { ok: true, password: "pw" });
  assert.deepEqual(await send({ type: "totp", id: "e1" }), { ok: true, code: "123456", remaining: 12, period: 30 });
});

test("add validates and forwards only the documented fields", async () => {
  world.posted = [];
  world.respond = (m) => (m.cmd === "add" ? { ok: true, id: "new-1" } : null);
  const reply = await send({ type: "add", title: " Site ", password: "pw", username: "", url: "https://site.example", category: "Work", extra: 1 });
  assert.deepEqual(reply, { ok: true, id: "new-1" });
  const { rid, ...posted } = world.posted[0];
  assert.ok(Number.isInteger(rid));
  assert.deepEqual(posted, { cmd: "add", title: "Site", password: "pw", url: "https://site.example", category: "Work" });
  assert.equal((await send({ type: "add", title: "", password: "pw" })).code, "invalid");
  assert.equal((await send({ type: "add", title: "x", password: "" })).code, "invalid");
});

test("editable, update and delete", async () => {
  world.posted = [];
  world.respond = (m) => {
    if (m.cmd === "get") {
      return { ok: true, entry: { id: 7, title: "Mail", username: null, url: "https://mail.example", password: "pw", category: null, notes: "Codes:\n 1 2", updated_at: 1700 } };
    }
    if (m.cmd === "update") return { ok: true, id: 7 };
    if (m.cmd === "delete") return { ok: true, trashed: true };
    return null;
  };
  assert.deepEqual(await send({ type: "editable", id: 7 }), {
    ok: true,
    entry: { id: 7, title: "Mail", username: "", password: "pw", url: "https://mail.example", category: "", notes: "Codes:\n 1 2", updatedAt: 1700 },
  });
  // Only the edit form reads the notes.
  assert.deepEqual(world.posted.find((m) => m.cmd === "get").notes, true);

  world.posted = [];
  const updated = await send({ type: "update", id: 7, updatedAt: 1700, title: " Mail ", password: "new", username: "", url: "", category: "Work" });
  assert.deepEqual(updated, { ok: true });
  const { rid, ...posted } = world.posted[0];
  assert.ok(Number.isInteger(rid));
  assert.deepEqual(posted, { cmd: "update", title: "Mail", password: "new", category: "Work", id: 7, updated_at: 1700 });

  // Notes keep their spacing; blank notes from the form clear them.
  world.posted = [];
  await send({ type: "update", id: 7, updatedAt: 1700, title: "Mail", password: "pw", notes: "  line 1\nline 2 " });
  assert.equal(world.posted[0].notes, "  line 1\nline 2 ");
  world.posted = [];
  await send({ type: "update", id: 7, updatedAt: 1700, title: "Mail", password: "pw", notes: " \n " });
  assert.equal(world.posted[0].notes, "");
  assert.equal((await send({ type: "update", id: 7, updatedAt: 1700, title: "Mail", password: "pw", notes: "x".repeat(65537) })).code, "invalid");
  assert.equal((await send({ type: "update", id: 7, title: "x", password: "y" })).code, "invalid");
  assert.equal((await send({ type: "update", id: 7, updatedAt: 1700, title: "x", password: "" })).code, "invalid");

  assert.deepEqual(await send({ type: "delete", id: 7 }), { ok: true, trashed: true });
  assert.equal((await send({ type: "delete" })).code, "invalid");

  // The host's own errors pass through.
  world.respond = (m) => ({ ok: false, code: m.cmd === "update" ? "changed" : "not_found", error: "x" });
  assert.equal((await send({ type: "update", id: 7, updatedAt: 1, title: "x", password: "y" })).code, "changed");
  assert.equal((await send({ type: "delete", id: 7 })).code, "not_found");
});

test("an older host that cannot edit reports host_outdated", async () => {
  world.respond = (m) => {
    if (m.cmd === "get") return { ok: true, entry: { id: 7, title: "Mail", password: "pw" } };
    return { ok: false, code: "invalid", error: `malformed request: unknown variant \`${m.cmd}\`, expected one of \`ping\`` };
  };
  assert.equal((await send({ type: "editable", id: 7 })).code, "host_outdated");
  assert.equal((await send({ type: "delete", id: 7 })).code, "host_outdated");
  assert.equal((await send({ type: "update", id: 7, updatedAt: 1, title: "x", password: "y" })).code, "host_outdated");
});

test("generate maps the generator options", async () => {
  world.posted = [];
  world.respond = () => ({ ok: true, password: "x" });
  await send({ type: "generate", options: { kind: "passphrase", passphrase: { words: 40, separator: "--+-", capitalize: false, number: true } } });
  const { rid, ...posted } = world.posted[0];
  assert.deepEqual(posted, { cmd: "generate", kind: "passphrase", words: 12, separator: "--+", capitalize: false, number: true });
});

test("fillPassword injects only the password into same-origin frames", async () => {
  world.tabs.set(11, "https://signup.example/new");
  world.scripts = [];
  world.posted = [];
  world.scriptResults = [{ frameId: 0, result: 2 }];
  const reply = await send({ type: "fillPassword", tabId: 11, password: "G3n!" });
  assert.deepEqual(reply, { ok: true, filled: 2 });
  assert.equal(world.scripts[0].func.name, "fillPasswordFields");
  assert.deepEqual(world.scripts[0].target, { tabId: 11, allFrames: true });
  assert.deepEqual(world.scripts[0].args, ["G3n!", "https://signup.example"]);
  assert.equal(world.posted.length, 0);
  world.tabs.set(12, "about:blank");
  assert.equal((await send({ type: "fillPassword", tabId: 12, password: "x" })).code, "not_web_page");
});

// ── Inline suggestions ──────────────────────────────────────────────────────

const MENU = (tabId, frameId = 9) => ({ id: EXT_ID, url: `${BASE}inline/menu.html`, tab: { id: tabId, url: world.tabs.get(tabId) }, frameId });
const CONTENT = (tabId, frameId, url) => ({ id: EXT_ID, url, tab: { id: tabId, url: world.tabs.get(tabId) }, frameId });

test("content scripts may only ask for a token; the menu only for its own types", async () => {
  world.tabs.set(20, "https://login.example/");
  world.posted = [];
  world.respond = () => ({ ok: true, entry: { password: "pw" }, entries: [] });
  const content = CONTENT(20, 0, "https://login.example/");
  for (const type of ["copy", "reveal", "list", "status", "inlineMenuState", "inlineFill", "favicons"]) {
    assert.equal(await send({ type, id: "e1", field: "password" }, content), undefined, type);
  }
  for (const type of ["copy", "reveal", "list", "fill", "inlineOpen"]) {
    assert.equal(await send({ type, id: "e1", field: "password", tabId: 20 }, MENU(20)), undefined, type);
  }
  assert.equal(world.posted.length, 0);
  // The popup cannot pretend to be a menu frame with a forged token.
  assert.equal((await send({ type: "inlineMenuState", token: "0".repeat(32) }, MENU(20))).code, "bad_token");
});

test("inline token flow: bound to tab + frame, single use", async () => {
  world.tabs.set(21, "https://login.example/signin");
  world.tabs.set(22, "https://other.example/");
  world.posted = [];
  world.scripts = [];
  world.scriptResults = [{ frameId: 3, result: 2 }];
  world.respond = (m) => {
    if (m.cmd === "status") return { ok: true, enabled: true, has_vault: true, unlocked: true };
    if (m.cmd === "match_url") return { ok: true, entries: [{ id: "e1", title: "Login", username: "me" }] };
    if (m.cmd === "fill") return { ok: true, username: "me", password: "pw" };
    return null;
  };

  const opened = await send({ type: "inlineOpen" }, CONTENT(21, 3, "https://login.example/frame"));
  assert.equal(opened.ok, true);
  assert.match(opened.token, /^[0-9a-f]{32}$/);
  const token = opened.token;

  // Another tab cannot use it.
  assert.equal((await send({ type: "inlineMenuState", token }, MENU(22))).code, "bad_token");

  const state = await send({ type: "inlineMenuState", token }, MENU(21, 9));
  assert.equal(state.state, "unlocked");
  assert.equal(state.host, "login.example");
  assert.equal(state.entries[0].id, "e1");
  // The URL comes from the tab, never from the message.
  assert.equal(world.posted.find((m) => m.cmd === "match_url").url, "https://login.example/signin");

  // Another menu frame of the same tab cannot use it once claimed.
  assert.equal((await send({ type: "inlineFill", token, id: "e1" }, MENU(21, 10))).code, "bad_token");

  const filled = await send({ type: "inlineFill", token, id: "e1", url: "https://evil.example/" }, MENU(21, 9));
  assert.deepEqual(filled, { ok: true, filled: 2 });
  const fillMsg = world.posted.find((m) => m.cmd === "fill");
  assert.equal(fillMsg.url, "https://login.example/signin");
  const call = world.scripts.at(-1);
  assert.deepEqual(call.target, { tabId: 21, frameIds: [3] });
  assert.deepEqual(call.args, ["me", "pw", "https://login.example"]);

  // Single use.
  assert.equal((await send({ type: "inlineFill", token, id: "e1" }, MENU(21, 9))).code, "bad_token");
});

test("inline: cross-origin frames get no token; navigation invalidates it", async () => {
  world.tabs.set(23, "https://top.example/");
  const refused = await send({ type: "inlineOpen" }, CONTENT(23, 4, "https://ads.example/frame"));
  assert.equal(refused.code, "cross_origin");

  const { token } = await send({ type: "inlineOpen" }, CONTENT(23, 0, "https://top.example/"));
  world.tabs.set(23, "https://elsewhere.example/");
  assert.equal((await send({ type: "inlineMenuState", token }, MENU(23))).code, "bad_token");
});

test("inline: locked vault and openPopup", async () => {
  world.tabs.set(24, "https://login.example/");
  world.respond = (m) => (m.cmd === "status" ? { ok: true, enabled: true, has_vault: true, unlocked: false, pin_available: true } : null);
  const { token } = await send({ type: "inlineOpen" }, CONTENT(24, 0, "https://login.example/"));
  const state = await send({ type: "inlineMenuState", token }, MENU(24));
  assert.deepEqual(state, { ok: true, state: "locked", pinAvailable: true, host: "login.example", entries: [] });

  const before = world.popupOpened;
  assert.deepEqual(await send({ type: "inlineOpenPopup", token, view: "add", open: false }, MENU(24)), { ok: true, opened: false });
  assert.equal(world.popupOpened, before);
  assert.deepEqual(await send({ type: "inlineOpenPopup", token, view: "add" }, MENU(24)), { ok: true, opened: true });
  assert.equal(world.popupOpened, before + 1);
  // The popup of that tab picks up the Add view once.
  assert.deepEqual(await send({ type: "takePendingView", tabId: 24 }), { ok: true, view: "add" });
  assert.deepEqual(await send({ type: "takePendingView", tabId: 24 }), { ok: true, view: null });
});

test("inlineSet registers and unregisters the content script", async () => {
  world.permitted = false;
  assert.equal((await send({ type: "inlineSet", enabled: true })).code, "permission_denied");
  assert.equal(world.registered.length, 0);

  world.permitted = true;
  assert.deepEqual(await send({ type: "inlineSet", enabled: true }), { ok: true, enabled: true });
  assert.deepEqual(world.registered, [
    { id: "ashypass-inline", js: ["inline/content.js"], matches: ["http://*/*", "https://*/*"], allFrames: true, runAt: "document_idle" },
  ]);
  // Idempotent.
  assert.deepEqual(await send({ type: "inlineState" }), { ok: true, enabled: true });
  assert.equal(world.registered.length, 1);

  // Off keeps the (required) site access and remembers the choice.
  assert.deepEqual(await send({ type: "inlineSet", enabled: false }), { ok: true, enabled: false });
  assert.equal(world.permitted, true);
  assert.equal(world.registered.length, 0);
  assert.equal(world.stored.inlineOff, true);
  assert.deepEqual(await send({ type: "inlineState" }), { ok: true, enabled: false });
  // On again.
  assert.deepEqual(await send({ type: "inlineSet", enabled: true }), { ok: true, enabled: true });
  assert.equal(world.registered.length, 1);
  assert.equal(world.stored.inlineOff, undefined);
});

test("a granted permission re-registers the script (permissions.onAdded)", async () => {
  world.permitted = true;
  world.registered = [];
  chrome.permissions.onAdded.fire({ origins: ["https://*/*"] });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(world.registered.length, 1);
  world.permitted = false;
  chrome.permissions.onRemoved.fire({ origins: ["https://*/*"] });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(world.registered.length, 0);
});
