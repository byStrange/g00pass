import { G00passError } from '../core';
import { h } from './dom';

/** Small building blocks shared by the screens. All text goes through text nodes. */

export const errMsg = (e: unknown) => (e instanceof G00passError ? e.message : e instanceof Error && e.name === 'AbortError' ? 'Cancelled.' : 'Unexpected error');

/** Step indicator: "1 Connect — 2 Verify admins — 3 Your key". */
export function stepper(steps: readonly string[], current: number): HTMLElement {
  return h(
    'ol',
    { class: 'stepper', 'aria-label': `Step ${current + 1} of ${steps.length}` },
    ...steps.map((s, i) =>
      h('li', { class: i < current ? 'done' : i === current ? 'current' : '', 'aria-current': i === current ? 'step' : false }, h('span', { class: 'dot' }, i < current ? '✓' : String(i + 1)), h('span', { class: 'label' }, s)),
    ),
  );
}

/** A focused, centered screen for one step of a flow. */
export function screen(opts: { steps?: readonly string[]; step?: number; title: string; lead?: string }, ...body: (Node | string | null | false)[]): HTMLElement {
  return h(
    'section',
    { class: 'screen' },
    opts.steps ? stepper(opts.steps, opts.step ?? 0) : null,
    h('h2', { class: 'screen-title' }, opts.title),
    opts.lead ? h('p', { class: 'lead' }, opts.lead) : null,
    ...body,
  );
}

let hintIds = 0;
export function field(label: string, input: HTMLElement, hint?: string): HTMLElement {
  let hintEl: HTMLElement | null = null;
  if (hint) {
    hintEl = h('span', { class: 'hint', id: `hint-${++hintIds}` }, hint);
    input.setAttribute('aria-describedby', hintEl.id);
  }
  return h('div', { class: 'field' }, h('label', { class: 'field-label-wrap' }, h('span', { class: 'field-label' }, label), input), hintEl);
}

export function notice(kind: 'info' | 'warn' | 'danger' | 'ok', ...text: (Node | string | null)[]): HTMLElement {
  return h('div', { class: `notice ${kind}`, role: kind === 'danger' ? 'alert' : false }, ...text);
}

/** "3F2A 9C0D …" full fingerprint, monospace, never truncated. */
export function fingerprint(fpr: string, big = false): HTMLElement {
  return h('span', { class: big ? 'fpr-big mono' : 'fpr mono', dir: 'ltr' }, (fpr.match(/.{1,4}/g) ?? []).join(' '));
}

/** The part an approver types: last 16 hex characters, grouped. */
export function fingerprintTail(fpr: string): HTMLElement {
  return h('span', { class: 'fpr-tail mono', dir: 'ltr' }, (fpr.slice(-16).match(/.{4}/g) ?? []).join(' '));
}

/**
 * A button that runs an async action: disabled with a busy label while it
 * runs, errors reported via `onError`.
 */
export function actionButton(label: string, run: () => Promise<void>, opts: { variant?: 'primary' | 'danger' | 'ghost'; busy?: string; onError: (msg: string) => void }): HTMLButtonElement {
  const b = h('button', { type: 'button', class: opts.variant ?? '' }, label);
  b.addEventListener('click', (e) => {
    e.preventDefault();
    void runBusy(b, label, opts.busy, run, opts.onError);
  });
  return b;
}

export async function runBusy(b: HTMLButtonElement, label: string, busy: string | undefined, run: () => Promise<void>, onError: (msg: string) => void): Promise<void> {
  if (b.disabled) return;
  b.disabled = true;
  b.textContent = busy ?? 'Working…';
  b.classList.add('busy');
  try {
    await run();
  } catch (e) {
    onError(errMsg(e));
  } finally {
    b.disabled = false;
    b.textContent = label;
    b.classList.remove('busy');
  }
}

/** A form whose submit runs `run` with the submit button in busy state. */
export function form(run: () => Promise<void>, onError: (msg: string) => void, submitLabel: string, busyLabel: string, ...children: (Node | string | null | false)[]): HTMLFormElement {
  const submit = h('button', { type: 'submit', class: 'primary' }, submitLabel);
  const f = h('form', { class: 'form' }, ...children, h('div', { class: 'actions' }, submit));
  f.addEventListener('submit', (e) => {
    e.preventDefault();
    void runBusy(submit, submitLabel, busyLabel, run, onError);
  });
  return f;
}

export function input(attrs: Record<string, string | boolean> = {}): HTMLInputElement {
  return h('input', { autocomplete: 'off', spellcheck: 'false', ...attrs });
}

/** Collapsible help. */
export function help(summary: string, ...body: (Node | string | null)[]): HTMLElement {
  return h('details', { class: 'help' }, h('summary', {}, summary), h('div', { class: 'help-body' }, ...body));
}

export const TOKEN_PAGE = 'https://github.com/settings/personal-access-tokens/new';

export function link(href: string, text: string): HTMLAnchorElement {
  return h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);
}

/** Step-by-step instructions to create a fine-grained token. */
export function tokenSteps(repos: string, permissions: string, expiry: string): HTMLElement {
  return h(
    'ol',
    { class: 'steps' },
    h('li', {}, 'Open ', link(TOKEN_PAGE, 'GitHub → Fine-grained tokens → Generate new token'), '.'),
    h('li', {}, 'Repository access: ', h('b', {}, 'Only select repositories'), ` → ${repos}.`),
    h('li', {}, 'Permissions: ', h('b', {}, permissions), '. Nothing else (Metadata: Read-only is added automatically).'),
    h('li', {}, `Expiration: ${expiry}. Generate, copy it, and paste it here.`),
  );
}
