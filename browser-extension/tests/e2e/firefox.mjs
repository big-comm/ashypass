// End-to-end in a real Firefox with the real native host and a throwaway
// vault, over WebDriver BiDi (Firefox's own remote protocol, which can
// install a temporary add-on): the same steps as chromium.mjs. Run through
// tests/e2e/run.sh, which gives Firefox a temporary HOME holding the native
// host registration.
//
//   node firefox.mjs <unpacked extension> <profile dir> <site port>
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { LOGIN, MASTER, serveLoginPage, until } from "./common.mjs";

const [extDir, profile, port] = process.argv.slice(2);
const FIREFOX = process.env.FIREFOX_BIN || "/usr/lib/firefox/firefox";
const EXT_ID = "ashypass@big-comm.github.io";
// Fixed internal UUID, so the popup's address is known.
const UUID = "a5b1c0de-0000-4000-8000-00000000e2e0";
const site = `http://127.0.0.1:${port}/login`;
const otherSite = `http://localhost:${port}/login`;

mkdirSync(profile, { recursive: true });
writeFileSync(
  `${profile}/user.js`,
  [
    `user_pref("extensions.webextensions.uuids", ${JSON.stringify(JSON.stringify({ [EXT_ID]: UUID }))});`,
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    'user_pref("signon.rememberSignons", false);',
  ].join("\n"),
);

// Access to sites, as when the user accepts the popup's "Enable" prompt
// (Firefox asks for MV3 host permissions; that prompt is browser UI).
writeFileSync(
  `${profile}/extension-preferences.json`,
  JSON.stringify({ [EXT_ID]: { permissions: [], origins: ["http://*/*", "https://*/*"] } }),
);

const server = await serveLoginPage(port);
const firefox = spawn(FIREFOX, ["-headless", "-no-remote", "-profile", profile, "--remote-debugging-port", "0", "-remote-allow-system-access"], {
  stdio: ["ignore", "ignore", "pipe"],
});
let stderr = "";
firefox.stderr.on("data", (d) => (stderr += d));
const wsUrl = await until("Firefox's remote protocol", () => stderr.match(/WebDriver BiDi listening on (ws:\/\/\S+)/)?.[1], 60000);

// A minimal BiDi client.
const ws = new WebSocket(`${wsUrl}/session`);
await new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = reject;
});
let nextId = 1;
const pending = new Map();
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.type === "error") reject(new Error(`${msg.error}: ${msg.message}`));
    else resolve(msg.result);
  }
};
const bidi = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });

/** Runs `fn` (source text of a function) in a browsing context. */
async function run(context, fn, ...args) {
  const result = await bidi("script.callFunction", {
    functionDeclaration: fn,
    target: { context },
    arguments: args.map((value) => ({ type: "string", value })),
    awaitPromise: true,
    userActivation: true,
  });
  if (result.type === "exception") throw new Error(result.exceptionDetails.text);
  return result.result;
}
const value = (r) => r?.value;
async function navigate(context, url) {
  await bidi("browsingContext.navigate", { context, url, wait: "complete" });
}
/** A real (trusted) click on the element `selector` finds in `context`. */
async function click(context, selector) {
  await bidi("browsingContext.activate", { context: topOf.get(context) ?? context }).catch(() => {});
  const node = await run(context, "(s) => document.querySelector(s)", selector);
  assert.ok(node?.sharedId, `no ${selector}`);
  await bidi("input.performActions", {
    context,
    actions: [
      {
        type: "pointer",
        id: "mouse",
        actions: [
          { type: "pointerMove", x: 0, y: 0, origin: { type: "element", element: { sharedId: node.sharedId } } },
          { type: "pointerDown", button: 0 },
          { type: "pointerUp", button: 0 },
        ],
      },
    ],
  });
}
async function type(context, selector, text) {
  await click(context, selector);
  await run(context, "(s) => { const el = document.querySelector(s); el.select?.(); }", selector);
  await bidi("input.performActions", {
    context,
    actions: [{ type: "key", id: "kbd", actions: [...text].flatMap((c) => [{ type: "keyDown", value: c }, { type: "keyUp", value: c }]) }],
  });
}
// Menu frames belong to a tab: activate the tab to click in them.
const topOf = new Map();
const visible = (context, selector) =>
  run(context, "(s) => { const el = document.querySelector(s); return !!el && !el.hidden && el.offsetParent !== null; }", selector).then(value);

try {
  await bidi("session.new", { capabilities: {} });
  const { extension } = await bidi("webExtension.install", { extensionData: { type: "path", path: extDir } });
  assert.equal(extension, EXT_ID);
  console.log("extension installed:", extension);
  const { contexts } = await bidi("browsingContext.getTree", {});
  const tab = contexts[0].context;


  // The login page: open the inline menu from the keyboard, as a user does.
  const menuOf = async (url) => {
    await navigate(tab, url);
    // The extension marks login fields once its script is in the page.
    await until("the extension in the page", () => run(tab, "() => !!document.querySelector('ashypass-badges')").then(value));
    // Click the Ashy Pass icon inside the field (headless Firefox fires no
    // focus events, which the keyboard shortcut path relies on).
    const at = JSON.parse(
      value(
        await run(
          tab,
          "() => { const r = document.querySelector('#user').getBoundingClientRect(); const size = Math.round(Math.min(22, Math.max(14, r.height - 12))); return JSON.stringify({ x: Math.round(r.right - 6 - size / 2), y: Math.round(r.top + r.height / 2) }); }",
        ),
      ),
    );
    await bidi("input.performActions", {
      context: tab,
      actions: [
        {
          type: "pointer",
          id: "mouse",
          actions: [
            { type: "pointerMove", x: at.x, y: at.y, origin: "viewport" },
            { type: "pointerDown", button: 0 },
            { type: "pointerUp", button: 0 },
          ],
        },
      ],
    });
    await bidi("input.releaseActions", { context: tab });
    const menu = await until("the inline menu", async () => {
      const tree = await bidi("browsingContext.getTree", { root: tab });
      const find = (nodes) => nodes.flatMap((n) => [n, ...find(n.children ?? [])]);
      return find(tree.contexts).find((c) => c.url.endsWith("/inline/menu.html"))?.context;
    });
    topOf.set(menu, tab);
    await until("the menu content", () => run(menu, "() => !document.querySelector('#menu-list').hidden || !document.querySelector('#state-message').hidden").then(value));
    return menu;
  };
  const titles = (menu) => run(menu, "() => JSON.stringify([...document.querySelectorAll('button.item .item-title')].map((e) => e.textContent))").then((r) => JSON.parse(value(r)));

  // The popup, in a tab the (extension) menu page opens: BiDi may not
  // navigate to extension pages itself. Locked first, then unlocked.
  const lockedFirst = await menuOf(site);
  assert.deepEqual(await titles(lockedFirst), [], "a locked vault lists nothing");
  console.log("locked: the menu lists nothing");
  await run(lockedFirst, "(u) => { window.open(u); }", `moz-extension://${UUID}/popup/popup.html`);
  const popup = await until("the popup tab", async () => {
    const { contexts } = await bidi("browsingContext.getTree", {});
    return contexts.find((c) => c.url.endsWith("/popup/popup.html"))?.context;
  });
  await until("the locked view", () => visible(popup, "#view-locked"));
  await type(popup, "#unlock-input", "not the password");
  await click(popup, "#unlock-submit");
  await until("the wrong-password message", async () => value(await run(popup, "() => document.querySelector('#unlock-error').textContent.trim()")));
  await type(popup, "#unlock-input", MASTER);
  await click(popup, "#unlock-submit");
  await until("the vault view", () => visible(popup, "#view-vault"));
  console.log("unlocked in the popup");

  const menu = await menuOf(site);
  await until("this site's login", async () => (await titles(menu)).includes(LOGIN.title));
  assert.deepEqual(await titles(menu), [LOGIN.title], "only this site's logins");
  await click(menu, "button.item");
  await until("the filled fields", async () => value(await run(tab, "() => document.querySelector('#pass').value")) === LOGIN.password);
  assert.equal(value(await run(tab, "() => document.querySelector('#user').value")), LOGIN.username);
  console.log("filled from the inline menu");

  const otherMenu = await menuOf(otherSite);
  assert.deepEqual(await titles(otherMenu), [], "no logins offered on another host");
  assert.equal(value(await run(tab, "() => document.querySelector('#pass').value")), "");
  console.log("nothing offered on another host");

  await click(popup, "#lock");
  await until("the locked view", () => visible(popup, "#view-locked"));
  const lockedMenu = await menuOf(site);
  assert.deepEqual(await titles(lockedMenu), [], "a locked vault lists nothing");
  console.log("locked: nothing listed");
  console.log("FIREFOX-E2E-OK");
} finally {
  try {
    await bidi("session.end");
  } catch {}
  ws.close();
  firefox.kill();
  server.close();
}
