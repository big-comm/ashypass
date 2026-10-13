// Static checks: JS syntax, manifests, locales, and the build output.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "src");
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));

const LOCALES = [
  "bg", "cs", "da", "de", "el", "en", "es", "et", "fi", "fr", "he", "hr", "hu", "is", "it",
  "ja", "ko", "nl", "no", "pl", "pt_BR", "pt_PT", "ro", "ru", "sk", "sv", "tr", "uk", "zh_CN",
];
const PERMISSIONS = ["nativeMessaging", "activeTab", "scripting", "clipboardWrite"];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "dist" || name === "node_modules" || name.startsWith(".")) continue;
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

test("node --check passes on every JS file", () => {
  const files = walk(ROOT).filter((f) => /\.(m?js)$/.test(f));
  assert.ok(files.length >= 4);
  for (const file of files) {
    execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
  }
});

test("no remote code, eval or inline scripts", () => {
  const files = walk(SRC).filter((f) => /\.(js|html)$/.test(f));
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /\beval\s*\(|new Function\s*\(|\binnerHTML\b|outerHTML|insertAdjacentHTML|document\.write/, file);
    assert.doesNotMatch(text, /https?:\/\/(?!www\.w3\.org)[^\s"'`]+\.(js|css)\b/, file);
    if (file.endsWith(".html")) {
      assert.doesNotMatch(text, /<script(?![^>]*\bsrc=)[^>]*>/, `${file}: inline <script>`);
      assert.doesNotMatch(text, /\son[a-z]+\s*=/, `${file}: inline event handler`);
      assert.doesNotMatch(text, /\sstyle\s*=/, `${file}: inline style`);
    }
  }
});

function checkCommon(m, label) {
  assert.equal(m.manifest_version, 3, label);
  assert.equal(m.default_locale, "en", label);
  assert.match(m.name, /^__MSG_\w+__$/, label);
  assert.match(m.description, /^__MSG_\w+__$/, label);
  assert.deepEqual(m.permissions, PERMISSIONS, label);
  assert.equal(m.host_permissions, undefined, label);
  assert.equal(m.optional_permissions, undefined, label);
  assert.equal(m.content_scripts, undefined, label);
  assert.equal(m.key, undefined, `${label}: key is added by build.py for chrome-dev only`);
  assert.equal(m.action.default_popup, "popup/popup.html", label);
  assert.equal(m.commands._execute_action.suggested_key.default, "Ctrl+Shift+L", label);
  const en = readJson(path.join(SRC, "_locales/en/messages.json"));
  for (const field of [m.name, m.description, m.action.default_title]) {
    const key = /^__MSG_(\w+)__$/.exec(field)?.[1];
    assert.ok(key && en[key], `${label}: ${field} missing in en`);
  }
  const files = [
    m.action.default_popup,
    ...Object.values(m.icons),
    ...Object.values(m.action.default_icon),
    ...(m.background.scripts ?? [m.background.service_worker]),
  ];
  for (const f of files) assert.ok(existsSync(path.join(SRC, f)), `${label}: ${f} missing`);
  for (const size of ["16", "32", "48", "96", "128"]) assert.ok(m.icons[size], `${label}: icon ${size}`);
}

test("Chrome manifest", () => {
  const m = readJson(path.join(ROOT, "manifest.chrome.json"));
  checkCommon(m, "chrome");
  assert.equal(m.background.service_worker, "background.js");
  assert.equal(m.background.type, "module");
  assert.equal(m.background.scripts, undefined);
  assert.equal(m.minimum_chrome_version, "116");
  assert.equal(m.browser_specific_settings, undefined);
});

test("Firefox manifest", () => {
  const m = readJson(path.join(ROOT, "manifest.firefox.json"));
  checkCommon(m, "firefox");
  assert.deepEqual(m.background.scripts, ["background.js"]);
  assert.equal(m.background.service_worker, undefined);
  assert.deepEqual(m.browser_specific_settings.gecko, {
    id: "ashypass@big-comm.github.io",
    strict_min_version: "140.0",
    data_collection_permissions: { required: ["none"] },
  });
});

test("VERSION and the development key", () => {
  assert.match(readFileSync(path.join(ROOT, "VERSION"), "utf8").trim(), /^\d+\.\d+\.\d+$/);
  const key = readFileSync(path.join(ROOT, "chrome-dev-key.pub"), "utf8").trim();
  assert.match(key, /^[A-Za-z0-9+/]+={0,2}$/);
});

const tokens = (s) => [...s.matchAll(/\$([A-Za-z0-9_@]+)\$/g)].map((m) => m[1].toLowerCase()).sort();

test("every locale exists and has exactly the keys of en, with consistent placeholders", () => {
  const dirs = readdirSync(path.join(SRC, "_locales")).sort();
  assert.deepEqual(dirs, [...LOCALES].sort());
  const en = readJson(path.join(SRC, "_locales/en/messages.json"));
  const enKeys = Object.keys(en).sort();

  for (const loc of LOCALES) {
    const file = path.join(SRC, "_locales", loc, "messages.json");
    const msgs = readJson(file);
    assert.deepEqual(Object.keys(msgs).sort(), enKeys, `${loc}: keys differ from en`);
    let translated = 0;
    for (const key of enKeys) {
      const { message, placeholders } = msgs[key];
      assert.equal(typeof message, "string", `${loc}.${key}`);
      assert.ok(message.trim() !== "", `${loc}.${key} is empty`);
      assert.deepEqual(tokens(message), tokens(en[key].message), `${loc}.${key}: placeholder tokens`);
      assert.deepEqual(placeholders ?? null, en[key].placeholders ?? null, `${loc}.${key}: placeholders object`);
      // A "$" that is not part of a $NAME$ token or "$$" breaks the i18n API.
      const stray = message.replace(/\$[A-Za-z0-9_@]+\$/g, "").replace(/\$\$/g, "");
      assert.ok(!stray.includes("$"), `${loc}.${key}: stray $`);
      if (message !== en[key].message) translated += 1;
    }
    if (loc !== "en") {
      // Everything but the product name must be translated.
      assert.ok(translated >= enKeys.length - 1, `${loc}: only ${translated}/${enKeys.length} translated`);
    }
  }
});

test("every data-i18n key used by the popup exists", () => {
  const en = readJson(path.join(SRC, "_locales/en/messages.json"));
  const html = readFileSync(path.join(SRC, "popup/popup.html"), "utf8");
  const js = readFileSync(path.join(SRC, "popup/popup.js"), "utf8");
  const used = new Set([
    ...[...html.matchAll(/data-i18n(?:-placeholder)?="(\w+)"/g)].map((m) => m[1]),
    ...[...js.matchAll(/\bt\("(\w+)"/g)].map((m) => m[1]),
  ]);
  for (const key of used) assert.ok(en[key], `missing message ${key}`);
});

test("build.py produces clean dev trees and store zips", () => {
  const out = mkdtempSync(path.join(tmpdir(), "ashypass-build-"));
  try {
    execFileSync("python3", ["-I", path.join(ROOT, "build.py"), "--out", out], { stdio: "pipe" });
    const version = readFileSync(path.join(ROOT, "VERSION"), "utf8").trim();
    const key = readFileSync(path.join(ROOT, "chrome-dev-key.pub"), "utf8").trim();

    const chromeDev = readJson(path.join(out, "chrome-dev/manifest.json"));
    assert.equal(chromeDev.key, key);
    assert.equal(chromeDev.version, version);
    assert.ok(!existsSync(path.join(out, "chrome-dev/_locales/is")));
    assert.ok(existsSync(path.join(out, "chrome-dev/_locales/pt_BR/messages.json")));

    const firefoxDev = readJson(path.join(out, "firefox-dev/manifest.json"));
    assert.equal(firefoxDev.key, undefined);
    assert.ok(existsSync(path.join(out, "firefox-dev/_locales/is/messages.json")));

    const listZip = (name) =>
      execFileSync("python3", ["-I", "-c", "import sys,zipfile; print('\\n'.join(zipfile.ZipFile(sys.argv[1]).namelist()))", path.join(out, name)])
        .toString()
        .trim()
        .split("\n");
    const readZip = (name, member) =>
      execFileSync("python3", ["-I", "-c", "import sys,zipfile; sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]).decode())", path.join(out, name), member]).toString();

    const chromeZip = `ashypass-chrome-${version}.zip`;
    const chromeNames = listZip(chromeZip);
    assert.ok(chromeNames.includes("manifest.json"));
    assert.ok(chromeNames.includes("background.js"));
    assert.ok(!chromeNames.some((n) => n.startsWith("_locales/is/")));
    const chromeManifest = JSON.parse(readZip(chromeZip, "manifest.json"));
    assert.equal(chromeManifest.key, undefined);
    assert.equal(chromeManifest.version, version);

    const firefoxZip = `ashypass-firefox-${version}.zip`;
    const firefoxNames = listZip(firefoxZip);
    assert.ok(firefoxNames.includes("_locales/is/messages.json"));
    assert.ok(firefoxNames.includes("lib/fill.js"));
    assert.equal(JSON.parse(readZip(firefoxZip, "manifest.json")).browser_specific_settings.gecko.id, "ashypass@big-comm.github.io");
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
