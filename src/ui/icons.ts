/**
 * Inline SVG icons (stroke style, 24x24), built with createElementNS so the
 * strict CSP needs nothing extra. Decorative by default (aria-hidden).
 */
const PATHS: Record<string, string[]> = {
  lock: ['M6 11h12v9H6z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
  unlock: ['M6 11h12v9H6z', 'M8.5 11V8a3.5 3.5 0 0 1 6.8-1.2'],
  key: ['M14.5 9.5m-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0 -9 0', 'M11.2 12.8L4 20', 'M6.5 17.5l2 2', 'M8.5 15.5l1.5 1.5'],
  folder: ['M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h8.5A1.5 1.5 0 0 1 21 9.5v8A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z'],
  users: ['M9 8m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0', 'M3.5 19a5.5 5.5 0 0 1 11 0', 'M16 5.5a3 3 0 0 1 0 5.5', 'M17.5 14a5 5 0 0 1 3 5'],
  settings: ['M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0', 'M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8'],
  plus: ['M12 5v14', 'M5 12h14'],
  search: ['M11 11m-6 0a6 6 0 1 0 12 0a6 6 0 1 0 -12 0', 'M20 20l-4.5-4.5'],
  copy: ['M9 9h11v11H9z', 'M15 9V4H4v11h5'],
  eye: ['M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z', 'M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0'],
  eyeOff: ['M3 3l18 18', 'M10.6 6a9.6 9.6 0 0 1 1.4-.1C18 5.9 21.5 12 21.5 12a16 16 0 0 1-3 3.6', 'M6.4 7.1A16.2 16.2 0 0 0 2.5 12S6 18.5 12 18.5a9.3 9.3 0 0 0 4.4-1.1', 'M9.9 9.9a3 3 0 0 0 4.2 4.2'],
  edit: ['M4 20h4L19 9l-4-4L4 16z', 'M13.5 6.5l4 4'],
  trash: ['M4 7h16', 'M10 11v6M14 11v6', 'M6 7l1 13h10l1-13', 'M9 7V4h6v3'],
  shield: ['M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z', 'M8.5 12l2.5 2.5 4.5-5'],
  alert: ['M12 3l10 18H2z', 'M12 10v4.5', 'M12 17.5v.5'],
  check: ['M5 12.5l4.5 4.5L19 7.5'],
  x: ['M6 6l12 12M18 6L6 18'],
  refresh: ['M20 11a8 8 0 0 0-14.5-4.5L4 8', 'M4 4v4h4', 'M4 13a8 8 0 0 0 14.5 4.5L20 16', 'M20 20v-4h-4'],
  sparkle: ['M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z', 'M19 16l.7 1.8L21.5 18.5l-1.8.7L19 21l-.7-1.8-1.8-.7 1.8-.7z'],
  mail: ['M3 6h18v12H3z', 'M3.5 6.5L12 13l8.5-6.5'],
  logout: ['M10 4H5v16h5', 'M14 8l4 4-4 4', 'M18 12H9'],
  chevronRight: ['M9 6l6 6-6 6'],
  arrowLeft: ['M19 12H5', 'M11 6l-6 6 6 6'],
  info: ['M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0', 'M12 11v6', 'M12 7.5v.5'],
  link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  github: ['M9 19c-4 1.3-4-2-6-2.5m12 4.5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21'],
  inbox: ['M3 13l3-8h12l3 8v6H3z', 'M3 13h5l1.5 2.5h5L16 13h5'],
  clock: ['M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0', 'M12 7v5l3 2'],
};

export type IconName = keyof typeof PATHS;

export function icon(name: IconName, opts: { size?: number; label?: string; cls?: string } = {}): SVGSVGElement {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  const size = String(opts.size ?? 18);
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('class', `icon${opts.cls ? ' ' + opts.cls : ''}`);
  if (opts.label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', opts.label);
  } else {
    svg.setAttribute('aria-hidden', 'true');
  }
  for (const d of PATHS[name] ?? []) {
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}
