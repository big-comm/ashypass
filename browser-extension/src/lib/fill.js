// The function injected into the page by scripting.executeScript.
//
// It is serialised and run in the page's isolated world, so it must be fully
// self-contained: no imports, no references to anything outside its body.
// It runs in every frame (allFrames) but does nothing in frames whose origin
// differs from the tab's top-level origin, so a cross-origin iframe never
// receives credentials. It never submits the form.
//
// Returns the number of fields it filled in this frame.

export function fillCredentials(username, password, pageOrigin) {
  try {
    if (typeof location === "undefined" || location.origin !== pageOrigin) return 0;

    const USER_HINT = /user|login|e-?mail|account|ident|log_?in|signin/i;
    const TEXT_TYPES = new Set(["text", "email", "tel"]);
    const FOLLOWING = 4; // Node.DOCUMENT_POSITION_FOLLOWING

    const isUsable = (el) => {
      if (el.disabled || el.readOnly) return false;
      if (typeof el.getClientRects === "function" && el.getClientRects().length === 0) return false;
      const style = getComputedStyle(el);
      return style.visibility !== "hidden" && style.visibility !== "collapse" && style.display !== "none";
    };
    const autocompleteTokens = (el) =>
      String(el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).filter(Boolean);
    const userScore = (el) => {
      const ac = autocompleteTokens(el);
      if (ac.includes("one-time-code")) return -1;
      let score = 0;
      if (ac.includes("username")) score += 100;
      else if (ac.includes("email")) score += 80;
      if (USER_HINT.test(el.name || "") || USER_HINT.test(el.id || "")) score += 50;
      if (el.type === "email") score += 20;
      return score;
    };
    const pickBest = (fields, preferLast) => {
      let best = null;
      let bestScore = -1;
      for (const el of fields) {
        const s = userScore(el);
        if (s < 0) continue;
        if (s > bestScore || (preferLast && s === bestScore)) {
          best = el;
          bestScore = s;
        }
      }
      return best;
    };

    // A field drawn almost invisible (over a decoy) is not filled: the
    // opacities of it and its ancestors multiplied, or a hidden ancestor.
    const concealed = (el) => {
      let opacity = 1;
      for (let node = el; node instanceof Element; node = node.parentElement ?? node.getRootNode?.().host) {
        const style = getComputedStyle(node);
        if (style.visibility !== "visible" || style.display === "none") return true;
        opacity *= Number(style.opacity);
        if (!(opacity >= 0.5)) return true;
      }
      return false;
    };

    const inputs = Array.from(document.querySelectorAll("input"));
    const passwordField = inputs.find((el) => el.type === "password" && isUsable(el)) || null;
    if (passwordField && concealed(passwordField)) return 0;
    const textFields = inputs.filter((el) => TEXT_TYPES.has(el.type) && isUsable(el));

    let usernameField = null;
    if (passwordField) {
      const form = passwordField.form || null;
      const before = textFields.filter(
        (el) => (el.form || null) === form && (el.compareDocumentPosition(passwordField) & FOLLOWING) !== 0,
      );
      // Highest score wins; on a tie, the field closest to the password.
      usernameField = pickBest(before, true);
    } else {
      // Two-step login: only a clearly identified username field.
      usernameField = pickBest(textFields.filter((el) => userScore(el) > 0), false);
    }

    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    const put = (el, value) => {
      el.focus();
      setter.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    };

    let filled = 0;
    if (usernameField && typeof username === "string" && username !== "") {
      put(usernameField, username);
      filled += 1;
    }
    if (passwordField && typeof password === "string" && password !== "") {
      put(passwordField, password);
      filled += 1;
    }
    if (passwordField && filled > 0) passwordField.focus();
    return filled;
  } catch {
    return 0;
  } finally {
    username = null;
    password = null;
  }
}

// Fills a generated password into the page's password fields (for example
// "new password" and "confirm password"). Same rules as fillCredentials:
// self-contained, same-origin frames only, never submits. Fields of the form
// that holds the focused (or first) password field are filled; at most 3.
//
// Returns the number of fields it filled in this frame.

export function fillPasswordFields(password, pageOrigin) {
  try {
    if (typeof location === "undefined" || location.origin !== pageOrigin) return 0;
    if (typeof password !== "string" || password === "") return 0;

    const isUsable = (el) => {
      if (el.disabled || el.readOnly) return false;
      if (typeof el.getClientRects === "function" && el.getClientRects().length === 0) return false;
      const style = getComputedStyle(el);
      return style.visibility !== "hidden" && style.visibility !== "collapse" && style.display !== "none";
    };

    const fields = Array.from(document.querySelectorAll("input")).filter(
      (el) => el.type === "password" && isUsable(el),
    );
    if (fields.length === 0) return 0;
    const active = document.activeElement;
    const anchor = fields.includes(active) ? active : fields[0];
    const form = anchor.form || null;
    const targets = fields.filter((el) => (el.form || null) === form).slice(0, 3);

    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    for (const el of targets) {
      el.focus();
      setter.call(el, password);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }
    anchor.focus();
    return targets.length;
  } catch {
    return 0;
  } finally {
    password = null;
  }
}
