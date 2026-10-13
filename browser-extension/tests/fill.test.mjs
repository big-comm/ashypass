// Runs the real injected function against a tiny fake DOM.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { fillCredentials, fillPasswordFields } from "../src/lib/fill.js";

const ORIGIN = "https://example.com";

class FakeInputBase {
  get value() {
    return this._value ?? "";
  }
  set value(v) {
    this._value = String(v);
    this.nativeSets = (this.nativeSets ?? 0) + 1;
  }
}

class FakeInput extends FakeInputBase {
  constructor(doc, order, opts = {}) {
    super();
    this.doc = doc;
    this.order = order;
    this.type = opts.type ?? "text";
    this.name = opts.name ?? "";
    this.id = opts.id ?? "";
    this.form = opts.form ?? null;
    this.disabled = opts.disabled ?? false;
    this.readOnly = opts.readOnly ?? false;
    this.visible = opts.visible ?? true;
    this.visibility = opts.visibility ?? "visible";
    this.autocomplete = opts.autocomplete ?? null;
    this.events = [];
  }
  getAttribute(name) {
    return name === "autocomplete" ? this.autocomplete : null;
  }
  getClientRects() {
    return this.visible ? [{ width: 100, height: 20 }] : [];
  }
  compareDocumentPosition(other) {
    return other.order > this.order ? 4 : 2;
  }
  focus() {
    this.doc.activeElement = this;
  }
  dispatchEvent(event) {
    this.events.push({ type: event.type, bubbles: event.bubbles });
    return true;
  }
}

function makeDoc(specs) {
  const doc = { activeElement: null, inputs: [] };
  doc.inputs = specs.map((spec, i) => new FakeInput(doc, i, spec));
  doc.querySelectorAll = (sel) => {
    assert.equal(sel, "input");
    return doc.inputs;
  };
  return doc;
}

const saved = {};
const GLOBALS = ["location", "document", "getComputedStyle", "HTMLInputElement"];

beforeEach(() => {
  for (const g of GLOBALS) saved[g] = Object.getOwnPropertyDescriptor(globalThis, g);
  globalThis.location = { origin: ORIGIN };
  globalThis.getComputedStyle = (el) => ({ visibility: el.visibility, display: "inline-block" });
  globalThis.HTMLInputElement = FakeInputBase;
});

afterEach(() => {
  for (const g of GLOBALS) {
    if (saved[g]) Object.defineProperty(globalThis, g, saved[g]);
    else delete globalThis[g];
  }
});

function run(specs, { user = "alice", pass = "s3cret", origin = ORIGIN } = {}) {
  const doc = makeDoc(specs);
  globalThis.document = doc;
  const count = fillCredentials(user, pass, origin);
  return { count, doc, inputs: doc.inputs };
}

test("fills a plain username + password form and focuses the password", () => {
  const form = {};
  const { count, doc, inputs } = run([
    { type: "text", name: "q" }, // search box outside the form
    { type: "text", name: "login", form },
    { type: "password", name: "pw", form },
  ]);
  assert.equal(count, 2);
  assert.equal(inputs[0].value, "");
  assert.equal(inputs[1].value, "alice");
  assert.equal(inputs[2].value, "s3cret");
  assert.equal(doc.activeElement, inputs[2]);
  assert.deepEqual(inputs[2].events, [
    { type: "input", bubbles: true },
    { type: "change", bubbles: true },
  ]);
});

test("does nothing in a frame of another origin", () => {
  const { count, inputs } = run([{ type: "text", name: "user" }, { type: "password" }], {
    origin: "https://other.example",
  });
  assert.equal(count, 0);
  assert.equal(inputs[0].value, "");
  assert.equal(inputs[1].value, "");
});

test("skips hidden, disabled and readonly password fields", () => {
  const { count, inputs } = run([
    { type: "password", visible: false },
    { type: "password", disabled: true },
    { type: "password", readOnly: true },
    { type: "password", visibility: "hidden" },
    { type: "email", name: "email" },
    { type: "password", name: "real" },
  ]);
  assert.equal(count, 2);
  assert.equal(inputs[5].value, "s3cret");
  assert.equal(inputs[4].value, "alice");
  for (const i of [0, 1, 2, 3]) assert.equal(inputs[i].value, "");
});

test("prefers autocomplete=username over a closer unnamed field", () => {
  const { inputs } = run([
    { type: "text", name: "x", autocomplete: "username" },
    { type: "text", name: "nickname" },
    { type: "password" },
  ]);
  assert.equal(inputs[0].value, "alice");
  assert.equal(inputs[1].value, "");
});

test("on a tie takes the field closest to the password", () => {
  const { inputs } = run([{ type: "text", name: "a" }, { type: "text", name: "b" }, { type: "password" }]);
  assert.equal(inputs[0].value, "");
  assert.equal(inputs[1].value, "alice");
});

test("ignores text fields after the password and in other forms", () => {
  const f1 = {};
  const f2 = {};
  const { count, inputs } = run([
    { type: "text", name: "username", form: f2 },
    { type: "password", form: f1 },
    { type: "text", name: "user2", form: f1 },
  ]);
  assert.equal(count, 1);
  assert.equal(inputs[0].value, "");
  assert.equal(inputs[2].value, "");
  assert.equal(inputs[1].value, "s3cret");
});

test("ignores one-time-code fields", () => {
  const { inputs } = run([{ type: "text", autocomplete: "one-time-code", name: "login" }, { type: "password" }]);
  assert.equal(inputs[0].value, "");
});

test("two-step login: fills only a recognised username field", () => {
  const { count, doc, inputs } = run([
    { type: "search", name: "q" },
    { type: "text", name: "comment" },
    { type: "email", id: "identifierId" },
  ]);
  assert.equal(count, 1);
  assert.equal(inputs[1].value, "");
  assert.equal(inputs[2].value, "alice");
  assert.equal(doc.activeElement, inputs[2]);
});

test("two-step login without a recognisable field fills nothing", () => {
  const { count } = run([{ type: "text", name: "comment" }, { type: "search", name: "q" }]);
  assert.equal(count, 0);
});

test("uses the native value setter even when the instance shadows value (React)", () => {
  const doc = makeDoc([{ type: "text", name: "username" }, { type: "password" }]);
  let shadowSets = 0;
  for (const el of doc.inputs) {
    Object.defineProperty(el, "value", {
      configurable: true,
      get: () => "",
      set: () => {
        shadowSets += 1;
      },
    });
  }
  globalThis.document = doc;
  assert.equal(fillCredentials("alice", "s3cret", ORIGIN), 2);
  assert.equal(shadowSets, 0);
  assert.equal(doc.inputs[0]._value, "alice");
  assert.equal(doc.inputs[1]._value, "s3cret");
});

test("empty username fills only the password", () => {
  const { count, inputs } = run([{ type: "text", name: "user" }, { type: "password" }], { user: "" });
  assert.equal(count, 1);
  assert.equal(inputs[0].value, "");
});

test("no fields at all returns 0 and never throws", () => {
  assert.equal(run([]).count, 0);
  globalThis.document = { querySelectorAll() { throw new Error("boom"); } };
  assert.equal(fillCredentials("a", "b", ORIGIN), 0);
});

test("is self-contained (safe to serialise for executeScript)", () => {
  const source = fillCredentials.toString();
  assert.ok(source.startsWith("function fillCredentials("));
  assert.doesNotMatch(source, /\bimport\b|\brequire\(|\bapi\.|\bchrome\.|\bbrowser\./);
  // Rebuild it from its source alone, as the browser does.
  const rebuilt = new Function(`return (${source});`)();
  globalThis.document = makeDoc([{ type: "text", name: "user" }, { type: "password" }]);
  assert.equal(rebuilt("alice", "s3cret", ORIGIN), 2);
});

// ── fillPasswordFields (generator "Fill on this page") ──────────────────────

function runPassword(specs, { pass = "G3n!", origin = ORIGIN, active = null } = {}) {
  const doc = makeDoc(specs);
  if (active !== null) doc.activeElement = doc.inputs[active];
  globalThis.document = doc;
  return { count: fillPasswordFields(pass, origin), doc, inputs: doc.inputs };
}

test("fillPasswordFields fills new + confirm password of one form, never the username", () => {
  const form = {};
  const { count, inputs, doc } = runPassword([
    { type: "text", name: "user", form },
    { type: "password", name: "new", form },
    { type: "password", name: "confirm", form },
  ]);
  assert.equal(count, 2);
  assert.equal(inputs[0].value, "");
  assert.equal(inputs[1].value, "G3n!");
  assert.equal(inputs[2].value, "G3n!");
  assert.equal(doc.activeElement, inputs[1]);
});

test("fillPasswordFields prefers the form of the focused password field", () => {
  const login = {};
  const signup = {};
  const { count, inputs } = runPassword(
    [
      { type: "password", form: login },
      { type: "password", form: signup },
      { type: "password", form: signup },
    ],
    { active: 2 },
  );
  assert.equal(count, 2);
  assert.equal(inputs[0].value, "");
  assert.equal(inputs[1].value, "G3n!");
});

test("fillPasswordFields refuses other origins, hidden fields and empty values", () => {
  assert.equal(runPassword([{ type: "password" }], { origin: "https://evil.example" }).count, 0);
  assert.equal(runPassword([{ type: "password", visible: false }]).count, 0);
  assert.equal(runPassword([{ type: "password" }], { pass: "" }).count, 0);
  assert.equal(runPassword([]).count, 0);
});

test("fillPasswordFields is self-contained", () => {
  const source = fillPasswordFields.toString();
  assert.ok(source.startsWith("function fillPasswordFields("));
  assert.doesNotMatch(source, /\bimport\b|\brequire\(|\bapi\.|\bchrome\.|\bbrowser\./);
  const rebuilt = new Function(`return (${source});`)();
  globalThis.document = makeDoc([{ type: "password" }]);
  assert.equal(rebuilt("x", ORIGIN), 1);
});
