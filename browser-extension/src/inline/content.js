// Ashy Pass inline suggestions — content script (registered at runtime by the
// background unless the user turned the suggestions off in Settings).
//
// It never sees vault data. Like other password managers it marks every
// visible login field with the Ashy Pass icon; clicking the icon, or focusing
// the field, opens the suggestions menu below it.
// The menu is an <iframe> of an extension page (inline/menu.html), so the
// page cannot read it; this script only places and sizes the frame, and
// passes it an opening token issued by the background for this tab+frame.
// Classic script (no modules), self-contained.

(() => {
  "use strict";

  const api = globalThis.browser ?? globalThis.chrome;
  if (!api?.runtime?.id || globalThis.__ashypassInlineLoaded) return;
  globalThis.__ashypassInlineLoaded = true;

  // Only in the top frame or in frames of the same origin as the top page
  // (the background checks this again with the tab URL).
  function sameOriginAsTop() {
    try {
      if (window === window.top) return true;
      const ancestors = location.ancestorOrigins;
      if (ancestors && Array.from(ancestors).some((o) => o !== location.origin)) return false;
      return window.top.location.origin === location.origin;
    } catch {
      return false;
    }
  }
  if (!/^https?:$/.test(location.protocol) || !sameOriginAsTop()) return;

  const MENU_URL = api.runtime.getURL("inline/menu.html");
  const ICON_URL = api.runtime.getURL("icons/icon-48.png");
  const MAX_BADGES = 10;
  const BADGE_SCAN_MS = 400;
  const MENU_ORIGIN = new URL(MENU_URL).origin;
  const MENU_MIN_WIDTH = 280;
  const MENU_MAX_WIDTH = 380;
  const MENU_MAX_HEIGHT = 340;
  const GAP = 4;
  const MUTATION_THROTTLE_MS = 150;

  const TEXT_TYPES = new Set(["text", "email", "tel"]);
  const USER_HINT = /user|login|e-?mail|account|ident|log_?in|signin|sign_in|usuario|usuário|benutzer|courriel|utente/i;
  const EXCLUDE_HINT = /search|query|^q$|\botp\b|one.?time|totp|2fa|mfa|captcha|coupon|promo|verification|\bpin\b/i;

  let disabled = false;
  let field = null; // the login field the UI belongs to
  let host = null; // closed shadow root host
  let shadow = null;
  let button = null;
  let frame = null;
  let token = null;
  let menuHeight = 120;
  let suppressed = null; // field where Escape closed the menu (until clicked)
  let framePending = false;
  let observer = null;
  let mutationTimer = null;
  let rafPending = false;
  let openSeq = 0;
  // The browser's own password manager draws its list over the page, right
  // where our menu goes. While it is on, focusing a field only shows our icon
  // and the menu opens from the icon; once Ashy Pass turned it off
  // (Settings), the menu opens on the field like other password managers.
  let openOnFocus = false;
  try {
    Promise.resolve(api.storage.local.get("browserPmOff"))
      .then((stored) => {
        openOnFocus = stored?.browserPmOff === true;
      })
      .catch(() => {});
    api.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && "browserPmOff" in changes) openOnFocus = changes.browserPmOff.newValue === true;
    });
  } catch {
    // No storage: keep the icon-only behaviour.
  }
  const badges = new Map(); // login field -> its icon button
  let badgeHost = null;
  let badgeShadow = null;
  let badgeObserver = null;
  let badgeTimer = null;

  const i18n = (key) => {
    try {
      return api.i18n.getMessage(key) || key;
    } catch {
      return key;
    }
  };

  // ── Field detection ────────────────────────────────────────────────────

  const attr = (el, name) => String(el.getAttribute(name) || "");
  const acTokens = (el) => attr(el, "autocomplete").toLowerCase().split(/\s+/).filter(Boolean);

  function isVisible(el) {
    if (!el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 12) return false;
    const style = getComputedStyle(el);
    return style.visibility === "visible" && style.display !== "none" && Number(style.opacity) > 0.1;
  }

  /**
   * Whether `el` is shown faded out or hidden by its page: the opacities of
   * it and its ancestors multiplied together, or a hidden ancestor. A page
   * that draws its login field almost invisible over a decoy could trick
   * the user into clicking our menu, so no menu (nor filling) there.
   */
  function concealed(el) {
    let opacity = 1;
    for (let node = el; node instanceof Element; node = node.parentElement ?? node.getRootNode?.().host) {
      const style = getComputedStyle(node);
      if (style.visibility !== "visible" || style.display === "none") return true;
      opacity *= Number(style.opacity);
      if (!(opacity >= 0.5)) return true;
    }
    return false;
  }

  function scopeOf(el) {
    return el.form || el.closest("form") || el.getRootNode() || document;
  }

  function visiblePasswords(scope) {
    return Array.from(scope.querySelectorAll('input[type="password"]')).filter(isVisible);
  }

  function isLoginField(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
    const ac = acTokens(el);
    if (ac.includes("one-time-code")) return false;
    if (el.type === "password") return isVisible(el);
    if (!TEXT_TYPES.has(el.type)) return false;
    if (el.getAttribute("role") === "searchbox" || el.closest('[role="search"]')) return false;
    if (ac.includes("username") || ac.includes("email") || ac.includes("webauthn")) return isVisible(el);
    const hints = [el.name, el.id, attr(el, "placeholder"), attr(el, "aria-label")].join(" ");
    if (EXCLUDE_HINT.test(hints)) return false;
    const scope = scopeOf(el);
    const passwords = visiblePasswords(scope);
    if (passwords.length > 0) {
      if (USER_HINT.test(hints) || el.type === "email") return isVisible(el);
      // Otherwise only the text field right before the first password field.
      const texts = Array.from(scope.querySelectorAll("input")).filter(
        (i) => TEXT_TYPES.has(i.type) && isVisible(i) && (i.compareDocumentPosition(passwords[0]) & 4) !== 0,
      );
      return texts[texts.length - 1] === el;
    }
    // Two-step logins: a clearly named username field inside a form.
    return USER_HINT.test(hints) && (el.form !== null || el.closest("form") !== null) && isVisible(el);
  }

  // ── UI (closed shadow root, fixed position) ───────────────────────────

  function setStyles(el, styles) {
    for (const [name, value] of Object.entries(styles)) el.style.setProperty(name, value, "important");
  }

  const RESET = {
    all: "initial",
    position: "fixed",
    display: "block",
    visibility: "visible",
    opacity: "1",
    transform: "none",
    filter: "none",
    "clip-path": "none",
    margin: "0",
    padding: "0",
    border: "0",
    "z-index": "2147483647",
    "pointer-events": "auto",
  };

  /** The Ashy Pass app icon (web-accessible image of the extension). */
  function makeIcon() {
    const img = document.createElement("img");
    img.src = ICON_URL;
    img.alt = "";
    img.draggable = false;
    setStyles(img, { ...RESET, position: "static", width: "100%", height: "100%", "pointer-events": "none" });
    return img;
  }

  function ensureHost() {
    if (host?.isConnected) return;
    host = document.createElement("ashypass-inline");
    setStyles(host, { ...RESET, top: "0", left: "0", width: "0", height: "0", overflow: "visible" });
    shadow = host.attachShadow({ mode: "closed" });

    button = document.createElement("button");
    button.type = "button";
    button.tabIndex = -1;
    button.title = i18n("inlineButtonLabel");
    button.setAttribute("aria-label", i18n("inlineButtonLabel"));
    setStyles(button, {
      ...RESET,
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      width: "20px",
      height: "20px",
      background: "transparent",
      cursor: "pointer",
    });
    button.append(makeIcon());
    button.addEventListener("mousedown", (ev) => ev.preventDefault()); // keep the field focused
    button.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (!ev.isTrusted) return;
      suppressed = null;
      if (frame) closeMenu();
      else openMenu();
    });
    shadow.append(button);
    document.documentElement.append(host);
  }

  function attach(el, { open }) {
    if (disabled) return;
    if (field !== el) {
      closeMenu();
      field = el;
      suppressed = null;
    }
    ensureHost();
    position();
    watch();
    if (open && suppressed !== el) openMenu();
  }

  function detach() {
    closeMenu();
    field = null;
    unwatch();
    host?.remove();
    host = shadow = button = null;
    placeBadges(); // the field's own icon shows again
  }

  // ── Menu frame ─────────────────────────────────────────────────────────

  function send(message) {
    try {
      return Promise.resolve(api.runtime.sendMessage(message)).catch(() => null);
    } catch {
      return Promise.resolve(null);
    }
  }

  async function openMenu() {
    if (!field || disabled || frame || framePending || concealed(field)) return;
    framePending = true;
    const seq = ++openSeq;
    const reply = await send({ type: "inlineOpen" });
    framePending = false;
    if (seq !== openSeq || !field) return;
    if (!reply || reply.ok !== true || typeof reply.token !== "string") {
      if (reply?.code === "cross_origin") {
        disabled = true;
        badgeObserver?.disconnect();
        badgeHost?.remove();
        badges.clear();
        detach();
      }
      return;
    }
    ensureHost();
    token = reply.token;
    menuHeight = 120;
    frame = document.createElement("iframe");
    frame.src = MENU_URL;
    frame.title = i18n("inlineMenuTitle");
    frame.setAttribute("scrolling", "no");
    setStyles(frame, {
      ...RESET,
      width: `${MENU_MIN_WIDTH}px`,
      height: `${menuHeight}px`,
      "border-radius": "12px",
      "box-shadow": "0 4px 16px rgba(0,0,0,.22), 0 0 0 1px rgba(0,0,0,.08)",
      background: "transparent",
      "color-scheme": "normal",
    });
    shadow.append(frame);
    position();
  }

  function closeMenu() {
    openSeq += 1;
    framePending = false;
    token = null;
    if (frame) {
      frame.remove();
      frame = null;
    }
  }

  window.addEventListener("message", (ev) => {
    if (!frame || ev.source !== frame.contentWindow || ev.origin !== MENU_ORIGIN) return;
    const data = ev.data;
    if (!data || typeof data !== "object" || data.source !== "ashypass-menu") return;
    switch (data.type) {
      case "ready":
        if (token) frame.contentWindow.postMessage({ source: "ashypass-content", type: "init", token }, MENU_ORIGIN);
        break;
      case "resize":
        if (Number.isFinite(data.height)) {
          menuHeight = Math.max(40, Math.min(MENU_MAX_HEIGHT, Math.ceil(data.height)));
          position();
        }
        break;
      case "close":
        if (data.suppress) suppressed = field;
        closeMenu();
        field?.focus();
        break;
      case "filled":
        suppressed = field;
        closeMenu();
        break;
      case "focusField":
        field?.focus();
        break;
      default:
        break;
    }
  });

  // ── Placement ──────────────────────────────────────────────────────────

  /** Where the icon goes inside `el` (right edge, or left in RTL). */
  function iconPlace(el) {
    const r = el.getBoundingClientRect();
    const vw = document.documentElement.clientWidth || window.innerWidth;
    const vh = window.innerHeight;
    const hidden = r.bottom < 0 || r.top > vh || r.right < 0 || r.left > vw || r.width < 80;
    const size = Math.round(Math.min(22, Math.max(14, r.height - 12)));
    const rtl = getComputedStyle(el).direction === "rtl";
    const left = rtl ? r.left + 6 : r.right - size - 6;
    return { hidden, size, left: Math.round(left), top: Math.round(r.top + (r.height - size) / 2) };
  }

  function placeBadges() {
    for (const [el, badge] of badges) {
      const p = iconPlace(el);
      setStyles(badge, {
        // The focused field shows its own button at the same spot.
        display: p.hidden || el === field ? "none" : "flex",
        width: `${p.size}px`,
        height: `${p.size}px`,
        left: `${p.left}px`,
        top: `${p.top}px`,
      });
    }
  }

  function ensureBadgeHost() {
    if (badgeHost?.isConnected) return;
    badgeHost = document.createElement("ashypass-badges");
    setStyles(badgeHost, { ...RESET, top: "0", left: "0", width: "0", height: "0", overflow: "visible" });
    badgeShadow = badgeHost.attachShadow({ mode: "closed" });
    for (const badge of badges.values()) badgeShadow.append(badge);
    document.documentElement.append(badgeHost);
  }

  function makeBadge(el) {
    const badge = document.createElement("button");
    badge.type = "button";
    badge.tabIndex = -1;
    badge.title = i18n("inlineButtonLabel");
    badge.setAttribute("aria-label", i18n("inlineButtonLabel"));
    setStyles(badge, {
      ...RESET,
      display: "none",
      "align-items": "center",
      "justify-content": "center",
      background: "transparent",
      cursor: "pointer",
    });
    badge.append(makeIcon());
    badge.addEventListener("mousedown", (ev) => ev.preventDefault());
    badge.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (!ev.isTrusted || !el.isConnected) return;
      el.focus();
      suppressed = null;
      attach(el, { open: true });
    });
    return badge;
  }

  /** Mark the visible login fields of the page (at most MAX_BADGES). */
  function scanBadges() {
    if (disabled) return;
    const found = Array.from(document.querySelectorAll("input")).filter(isLoginField).slice(0, MAX_BADGES);
    for (const [el, badge] of badges) {
      if (!found.includes(el)) {
        badge.remove();
        badges.delete(el);
      }
    }
    if (found.length > 0) ensureBadgeHost();
    for (const el of found) {
      if (badges.has(el)) continue;
      const badge = makeBadge(el);
      badges.set(el, badge);
      badgeShadow.append(badge);
    }
    placeBadges();
  }

  function scheduleBadgeScan() {
    if (badgeTimer !== null) return;
    badgeTimer = setTimeout(() => {
      badgeTimer = null;
      scanBadges();
    }, BADGE_SCAN_MS);
  }

  function watchBadges() {
    if (badgeObserver) return;
    badgeObserver = new MutationObserver(scheduleBadgeScan);
    badgeObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden", "type"],
    });
  }

  function position() {
    placeBadges();
    if (!field || !button) return;
    const r = field.getBoundingClientRect();
    const vw = document.documentElement.clientWidth || window.innerWidth;
    const vh = window.innerHeight;
    const offscreen = r.bottom < 0 || r.top > vh || r.right < 0 || r.left > vw;
    const size = Math.round(Math.min(22, Math.max(14, r.height - 12)));
    const rtl = getComputedStyle(field).direction === "rtl";
    const left = rtl ? r.left + 6 : r.right - size - 6;
    setStyles(button, {
      display: offscreen || r.width < 80 ? "none" : "flex",
      width: `${size}px`,
      height: `${size}px`,
      left: `${Math.round(left)}px`,
      top: `${Math.round(r.top + (r.height - size) / 2)}px`,
    });
    if (!frame) return;
    if (offscreen) {
      setStyles(frame, { display: "none" });
      return;
    }
    const width = Math.min(Math.max(r.width, MENU_MIN_WIDTH), MENU_MAX_WIDTH, vw - 16);
    const x = Math.max(8, Math.min(rtl ? r.right - width : r.left, vw - width - 8));
    const below = vh - r.bottom - GAP - 8;
    const above = r.top - GAP - 8;
    const placeAbove = below < Math.min(menuHeight, 160) && above > below;
    const height = Math.max(40, Math.min(menuHeight, placeAbove ? above : below));
    const y = placeAbove ? r.top - GAP - height : r.bottom + GAP;
    setStyles(frame, {
      display: "block",
      width: `${Math.round(width)}px`,
      height: `${Math.round(height)}px`,
      left: `${Math.round(x)}px`,
      top: `${Math.round(y)}px`,
    });
  }

  function schedulePosition() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => {
      rafPending = false;
      position();
    });
  }

  // Throttled MutationObserver (SPAs move, hide or replace login forms).
  function watch() {
    if (observer) return;
    observer = new MutationObserver(() => {
      if (mutationTimer !== null) return;
      mutationTimer = setTimeout(() => {
        mutationTimer = null;
        if (!field) return;
        if (!isVisible(field)) detach();
        else schedulePosition();
      }, MUTATION_THROTTLE_MS);
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden"],
    });
  }

  function unwatch() {
    observer?.disconnect();
    observer = null;
    if (mutationTimer !== null) clearTimeout(mutationTimer);
    mutationTimer = null;
  }

  // ── Events ─────────────────────────────────────────────────────────────

  function deepActive() {
    let active = document.activeElement;
    while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
    return active;
  }

  const targetOf = (ev) => (typeof ev.composedPath === "function" ? ev.composedPath()[0] : ev.target);
  const isOurs = (ev) => host !== null && typeof ev.composedPath === "function" && ev.composedPath().includes(host);

  document.addEventListener(
    "focusin",
    (ev) => {
      if (disabled || isOurs(ev)) return;
      const el = targetOf(ev);
      if (el === field) return;
      if (isLoginField(el)) attach(el, { open: openOnFocus });
      else if (field) detach();
    },
    true,
  );

  document.addEventListener(
    "focusout",
    (ev) => {
      if (!field || targetOf(ev) !== field) return;
      // Focus moving into our menu frame shows up as the shadow host.
      setTimeout(() => {
        if (!field) return;
        if (deepActive() === field || document.activeElement === host) return;
        detach();
      }, 0);
    },
    true,
  );

  document.addEventListener(
    "pointerdown",
    (ev) => {
      // Only the user's own clicks and keys open the menu, never a page's
      // synthetic events.
      if (!ev.isTrusted || !field || isOurs(ev)) return;
      const el = targetOf(ev);
      if (el === field) {
        // A click on the field reopens a menu closed with Escape.
        suppressed = null;
        if (!frame && openOnFocus) openMenu();
        return;
      }
      // Focus was in the menu (not in the field): the whole UI goes away.
      if (deepActive() !== field) detach();
      else closeMenu();
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (ev) => {
      if (!ev.isTrusted || !field || targetOf(ev) !== field) return;
      if (ev.key === "Escape" && frame) {
        ev.stopPropagation();
        suppressed = field;
        closeMenu();
      } else if (ev.key === "ArrowDown" && frame && !ev.altKey) {
        ev.preventDefault();
        frame.focus();
        frame.contentWindow?.postMessage({ source: "ashypass-content", type: "focusList" }, MENU_ORIGIN);
      } else if (ev.key === "ArrowDown" && ev.altKey && !frame) {
        ev.preventDefault();
        suppressed = null;
        openMenu();
      }
    },
    true,
  );

  window.addEventListener("scroll", schedulePosition, { capture: true, passive: true });
  window.addEventListener("resize", schedulePosition, { passive: true });
  window.addEventListener("pagehide", detach);

  // A field that already has focus (autofocus): show the button, no menu.
  const initial = deepActive();
  if (initial && isLoginField(initial)) attach(initial, { open: false });

  // Mark every visible login field, and keep marking as the page changes.
  scanBadges();
  watchBadges();
})();
