// Small stroke icons (24×24), built with DOM APIs (createElementNS), no files.

const SVG_NS = "http://www.w3.org/2000/svg";

const ICONS = {
  copy: [["rect", { x: 9, y: 9, width: 12, height: 12, rx: 2 }], ["path", { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" }]],
  user: [["path", { d: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" }], ["circle", { cx: 12, cy: 7, r: 4 }]],
  key: [["circle", { cx: 7.5, cy: 15.5, r: 4.5 }], ["path", { d: "M10.7 12.3 21 2M16 7l3 3M18.5 4.5l2 2" }]],
  clock: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 7v5l3 2" }]],
  external: [["path", { d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3" }]],
  more: [
    ["circle", { cx: 12, cy: 5, r: 1.6, fill: "currentColor", stroke: "none" }],
    ["circle", { cx: 12, cy: 12, r: 1.6, fill: "currentColor", stroke: "none" }],
    ["circle", { cx: 12, cy: 19, r: 1.6, fill: "currentColor", stroke: "none" }],
  ],
  star: [["path", { d: "m12 2.5 2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5-4.8-4.6 6.6-.9z" }]],
  starFilled: [["path", { d: "m12 2.5 2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5-4.8-4.6 6.6-.9z", fill: "currentColor" }]],
  lock: [["rect", { x: 4, y: 11, width: 16, height: 10, rx: 2 }], ["path", { d: "M8 11V7a4 4 0 0 1 8 0v4" }]],
  back: [["path", { d: "M19 12H5M12 19l-7-7 7-7" }]],
  plus: [["path", { d: "M12 5v14M5 12h14" }]],
  eye: [["path", { d: "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" }], ["circle", { cx: 12, cy: 12, r: 3 }]],
  eyeOff: [
    ["path", { d: "M17.9 17.9A10 10 0 0 1 12 19c-6.4 0-10-7-10-7a18 18 0 0 1 5-5.9M9.9 5.2A9 9 0 0 1 12 5c6.4 0 10 7 10 7a18 18 0 0 1-2.2 3.2M14.1 14.1a3 3 0 0 1-4.2-4.2" }],
    ["path", { d: "M2 2l20 20" }],
  ],
  refresh: [["path", { d: "M21 4v6h-6M3 20v-6h6" }], ["path", { d: "M5.5 9a7.5 7.5 0 0 1 12.4-2.8L21 10M3 14l3.1 3.8A7.5 7.5 0 0 0 18.5 15" }]],
  vault: [["path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }]],
  generator: [["path", { d: "M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8 19 13M17.8 6.2 19 5M12.2 6.2 11 5M3 21l9-9" }]],
  settings: [["path", { d: "M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6" }]],
  search: [["circle", { cx: 11, cy: 11, r: 7 }], ["path", { d: "m21 21-5-5" }]],
  globe: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" }]],
  folder: [["path", { d: "M21 18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2z" }]],
  app: [["path", { d: "M12 3v12M7 10l5 5 5-5M5 21h14" }]],
  help: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01" }]],
  shield: [["path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" }], ["path", { d: "m9 12 2 2 4-4" }]],
  keyboard: [["rect", { x: 2, y: 6, width: 20, height: 12, rx: 2 }], ["path", { d: "M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10" }]],
  info: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 16v-4M12 8h.01" }]],
  check: [["path", { d: "m5 12 5 5L20 7" }]],
  edit: [["path", { d: "M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" }]],
  trash: [["path", { d: "M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6" }]],
  fill: [["path", { d: "M4 12h11M11 8l4 4-4 4" }], ["path", { d: "M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" }]],
};

/** An inline SVG icon (decorative: aria-hidden). */
export function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.classList.add("icon");
  for (const [tag, attrs] of ICONS[name] ?? []) {
    const child = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) child.setAttribute(k, String(v));
    svg.append(child);
  }
  return svg;
}

/** Replaces the children of every `[data-icon]` element with its icon. */
export function applyIcons(root = document) {
  for (const el of root.querySelectorAll("[data-icon]")) {
    el.replaceChildren(icon(el.dataset.icon, Number(el.dataset.iconSize) || 18));
  }
}
