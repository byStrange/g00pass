import {
  dirname,
  entryFile,
  findGpgIdForEntry,
  folderTrustStatus,
  gpgIdFolder,
  idMatchesFingerprint,
  isHiddenEntry,
  listEntries,
  readEntry,
  readRecipientLines,
  wipe,
  type StoreSnapshot,
} from '../core';
import { errMsg, notice } from './components';
import { type AppCtx, folderLabel } from './context';
import { clear, h } from './dom';
import { type PendingRequest, loadPending, requestForm, waitingView } from './request';
import { copyWithAutoClear } from './session';

const CLIPBOARD_CLEAR_MS = 30_000;

/** Which governing folders (own `.gpg-id`) list `fpr` as a recipient. */
export async function accessibleFolders(snapshot: StoreSnapshot, fpr: string): Promise<{ all: string[]; mine: Set<string> }> {
  const all = snapshot.listFiles().filter((p) => p === '.gpg-id' || p.endsWith('/.gpg-id')).map(dirname).sort();
  const mine = new Set<string>();
  for (const f of all) {
    const lines = (await readRecipientLines(snapshot, f)) ?? [];
    if (lines.some((l) => idMatchesFingerprint(l.id, fpr))) mine.add(f);
  }
  return { all, mine };
}

export function secretsView(ctx: AppCtx): HTMLElement {
  const snapshot = ctx.snapshot()!;
  const key = ctx.session.unlockedKey!;
  const fpr = key.getFingerprint().toUpperCase();
  const search = h('input', { type: 'search', placeholder: 'Search secrets', 'aria-label': 'Search secrets', autocomplete: 'off', spellcheck: 'false' });
  const tree = h('nav', { class: 'tree', 'aria-label': 'Secrets' });
  const detail = h('section', { class: 'detail', 'aria-live': 'polite' });
  const el = h('div', { class: 'secrets' }, h('div', { class: 'pane-left' }, search, tree), detail);
  const entries = listEntries(snapshot).filter((e) => !isHiddenEntry(e));
  const has = (p: string) => snapshot.hasFile(p);
  const governing = (e: string) => gpgIdFolder(findGpgIdForEntry(has, e));
  let active: string | null = null;

  void accessibleFolders(snapshot, fpr).then(({ all, mine }) => {
    if (mine.size === 0) return void detail.replaceChildren(noAccess(ctx, all));
    const canRead = (e: string) => mine.has(governing(e));
    const renderTree = () => {
      clear(tree);
      const q = search.value.trim().toLowerCase();
      const shown = entries.filter((e) => !q || e.slice(0, -4).toLowerCase().includes(q));
      const groups = new Map<string, string[]>();
      for (const e of shown) {
        const d = dirname(e);
        groups.set(d, [...(groups.get(d) ?? []), e]);
      }
      if (!shown.length) tree.append(h('p', { class: 'hint' }, entries.length ? 'No match.' : 'This store has no secrets yet.'));
      for (const [d, list] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
        tree.append(
          h('div', { class: 'group' },
            h('div', { class: 'group-title' }, d ? `${d}/` : '/'),
            h('ul', {}, ...list.map((e) => {
              const ok = canRead(e);
              const name = e.slice(d ? d.length + 1 : 0, -4);
              return h('li', {}, h('button', {
                type: 'button',
                class: `entry${ok ? '' : ' locked'}${active === e ? ' active' : ''}`,
                title: ok ? e.slice(0, -4) : 'You are not a recipient of this folder',
                'aria-label': e.slice(0, -4),
                onclick: () => void open(e, ok),
              }, ok ? name : `🔒 ${name}`));
            })),
          ),
        );
      }
    };
    search.addEventListener('input', renderTree);
    renderTree();
    if (!active) detail.replaceChildren(h('div', { class: 'empty' }, h('p', {}, 'Pick a secret on the left.'), h('p', { class: 'hint' }, `You can read ${[...mine].map(folderLabel).join(', ')}.`)));

    async function open(e: string, ok: boolean) {
      active = e;
      renderTree();
      if (!ok) {
        detail.replaceChildren(h('h3', {}, e.slice(0, -4)), notice('info', `You are not a recipient of ${folderLabel(governing(e))}. Ask an admin for access.`));
        return;
      }
      const k = ctx.session.unlockedKey;
      if (!k) return ctx.rerender();
      detail.replaceChildren(h('p', { class: 'hint' }, 'Decrypting…'));
      let plain: Uint8Array | null = null;
      try {
        plain = await readEntry(snapshot, e, [k]);
        const text = new TextDecoder().decode(plain);
        const nl = text.indexOf('\n');
        const password = nl === -1 ? text : text.slice(0, nl).replace(/\r$/, '');
        const rest = nl === -1 ? '' : text.slice(nl + 1);
        const pw = h('code', { class: 'secret' }, '••••••••••');
        const more = h('pre', { class: 'details', hidden: true }, rest);
        let shown = false;
        const toggle = h('button', { type: 'button' }, 'Show');
        toggle.addEventListener('click', () => {
          shown = !shown;
          pw.textContent = shown ? password : '••••••••••';
          more.hidden = !shown;
          toggle.textContent = shown ? 'Hide' : 'Show';
        });
        const status = h('p', { class: 'hint' });
        detail.replaceChildren(
          h('h3', {}, e.slice(0, -4)),
          h('div', { class: 'secret-row' }, pw),
          h('div', { class: 'actions' },
            h('button', {
              type: 'button',
              class: 'primary',
              onclick: () => copyWithAutoClear(password, CLIPBOARD_CLEAR_MS, () => ctx.toast('Clipboard cleared.')).then(() => ctx.toast('Copied. The clipboard clears in 30 seconds.'), () => ctx.toast('Clipboard not available.', true)),
            }, 'Copy password'),
            toggle,
            h('button', { type: 'button', class: 'ghost', onclick: () => { active = null; renderTree(); detail.replaceChildren(); } }, 'Close')),
          rest ? more : '',
          status,
        );
        const st = await folderTrustStatus(snapshot, dirname(entryFile(e))).catch(() => null);
        if (st) status.replaceChildren(st.verified ? `✓ Recipients of ${folderLabel(st.folder)} are signed by an admin.` : h('span', { class: 'danger-text' }, `⚠ Recipients of ${folderLabel(st.folder)} are not verified (${st.reason ?? st.code}). Changes there are disabled.`));
      } catch (err) {
        detail.replaceChildren(notice('danger', errMsg(err)));
        ctx.toast(errMsg(err), true);
      } finally {
        wipe(plain);
      }
    }
  });
  return el;
}

/** The unlocked key is not a recipient anywhere: request access (or wait). */
function noAccess(ctx: AppCtx, folders: readonly string[]): HTMLElement {
  const c = ctx.config();
  const requestsRepo = c.requestsRepo?.trim() || `${c.owner}/${c.repo}`;
  const box = h('div', { class: 'no-access' });
  const ask = () =>
    box.replaceChildren(
      h('h3', {}, "You don't have access to any folder yet"),
      h('p', {}, 'Ask for access to a folder. Your admin approves it, then you can read its secrets here.'),
      requestForm({
        config: c,
        folder: folders.filter((f) => f !== ''),
        requestsRepo,
        token: () => ctx.tokens.get(),
        unlockedKey: () => ctx.session.unlockedKey,
        onSubmitted: (p) => wait(p),
        onError: (m) => ctx.toast(m, true),
      }),
    );
  const wait = (p: PendingRequest) => box.replaceChildren(h('h3', {}, 'Waiting for approval'), waitingView({ pending: p, token: () => ctx.tokens.get(), onApproved: () => void ctx.reload('Approved — welcome!'), onCancel: ask, onError: (m) => ctx.toast(m, true) }));
  const p = loadPending();
  const fpr = ctx.session.unlockedKey?.getFingerprint().toUpperCase();
  if (p && p.fingerprint === fpr) wait(p);
  else ask();
  return box;
}
