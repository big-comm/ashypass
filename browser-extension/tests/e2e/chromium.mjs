// End-to-end in a real Chromium with the real native host and a throwaway
// vault: unlock in the popup, fill from the inline menu, nothing for
// another site, lock. Run through tests/e2e/run.sh.
//
//   node chromium.mjs <unpacked extension> <user data dir> <site port>
import assert from "node:assert/strict";
import { chromium } from "playwright-core";
import { LOGIN, MASTER, serveLoginPage, until } from "./common.mjs";

const [extDir, userDataDir, port] = process.argv.slice(2);
const DEV_ID = "opelfkfheadglgamfephkfejfpcnlbck";
const site = `http://127.0.0.1:${port}/login`;
// Same page, other host: the login must not be offered or filled there.
const otherSite = `http://localhost:${port}/login`;

const server = await serveLoginPage(port);
const context = await chromium.launchPersistentContext(userDataDir, {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
});
try {
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
  const id = new URL(worker.url()).host;
  assert.equal(id, DEV_ID, "the development key gives the id the host allows");
  console.log("extension loaded:", id);

  // The popup (as a tab): locked first, then unlocked with the master password.
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${id}/popup/popup.html`);
  await popup.locator("#view-locked").waitFor({ state: "visible" });
  await popup.fill("#unlock-input", "not the password");
  await popup.click("#unlock-submit");
  await until("the wrong-password message", async () => (await popup.textContent("#unlock-error"))?.trim());
  await popup.fill("#unlock-input", MASTER);
  await popup.click("#unlock-submit");
  await popup.locator("#view-vault").waitFor({ state: "visible" });
  console.log("unlocked in the popup");

  // The login page: the inline menu offers the login and fills it.
  const page = await context.newPage();
  await page.goto(site);
  const menuItems = async (p) => {
    await p.click("#user");
    await p.keyboard.press("Alt+ArrowDown");
    const frame = await until("the inline menu", () => p.frames().find((f) => f.url().endsWith("/inline/menu.html")));
    await until("the menu content", async () => (await frame.locator("#menu-list:not([hidden]), #state-message:not([hidden])").count()) > 0);
    return frame;
  };
  const menu = await menuItems(page);
  const item = menu.locator("button.item", { hasText: LOGIN.title });
  await item.waitFor();
  assert.equal(await menu.locator("button.item", { hasText: "Other site" }).count(), 0, "only this site's logins");
  await item.click();
  await until("the filled fields", async () => (await page.inputValue("#pass")) === LOGIN.password);
  assert.equal(await page.inputValue("#user"), LOGIN.username);
  console.log("filled from the inline menu");

  // Another host: no suggestion.
  const other = await context.newPage();
  await other.goto(otherSite);
  const otherMenu = await menuItems(other);
  assert.equal(await otherMenu.locator("button.item").count(), 0, "no logins offered on another host");
  assert.equal(await other.inputValue("#pass"), "");
  console.log("nothing offered on another host");

  // Lock from the popup: the menu asks to unlock instead of listing.
  await popup.bringToFront();
  await popup.click("#lock");
  await popup.locator("#view-locked").waitFor({ state: "visible" });
  const again = await context.newPage();
  await again.goto(site);
  const lockedMenu = await menuItems(again);
  assert.equal(await lockedMenu.locator("button.item").count(), 0, "a locked vault lists nothing");
  console.log("locked: nothing listed");
  console.log("CHROMIUM-E2E-OK");
} finally {
  await context.close();
  server.close();
}
