// Shared pieces of the end-to-end tests: a local login page and the test
// vault's data (crates/ashypass-native-host/examples/e2e_vault.rs).
import http from "node:http";

export const MASTER = "correct horse battery";
export const LOGIN = { title: "Test login", username: "ana", password: "s3cret-P4ss!" };

const PAGE = `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
  <form id="login" action="#" onsubmit="return false">
    <label>User <input id="user" name="username" autocomplete="username"></label>
    <label>Password <input id="pass" name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
</body></html>`;

/** Serves the login page on 127.0.0.1:`port` (on both 127.0.0.1 and
 * localhost addresses, which are different sites for the vault). */
export function serveLoginPage(port) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(PAGE);
  });
  return new Promise((resolve) => server.listen(Number(port), "127.0.0.1", () => resolve(server)));
}

export async function until(what, check, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}
