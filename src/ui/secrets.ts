import {
  G00passError,
  GitHubApiError,
  GitHubSnapshot,
  GitHubWriter,
  TrustError,
  deleteSecret,
  dirname,
  entryFile,
  generatePassword,
  governingFolder,
  joinPath,
  saveSecret,
  secretPath,
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
import { errMsg, field, form, help, input, notice } from './components';
import { members, namesSentence } from './people';
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

export interface SecretsMemory {
  /** Secret to re-open after a reload (e.g. the one just saved). */
  selected: string | null;
}

/** Friendly text for a failed write. */
function writeError(e: unknown): string {
  if (e instanceof GitHubApiError && (e.status === 403 || e.status === 404)) return 'Your GitHub token can only read this repository. To add or change secrets it needs Contents: Read and write (Settings → Connection).';
  if (e instanceof TrustError) return `g00pass will not write here: the member list of ${folderLabel(e.folder)} is not verified (${e.reason}).`;
  return errMsg(e);
}

export function secretsView(ctx: AppCtx, memory: SecretsMemory = { selected: null }): HTMLElement {
  const snapshot = ctx.snapshot()!;
  const key = ctx.session.unlockedKey!;
  const fpr = key.getFingerprint().toUpperCase();
  const search = h('input', { type: 'search', placeholder: 'Search secrets', 'aria-label': 'Search secrets', autocomplete: 'off', spellcheck: 'false' });
  const newBtn = h('button', { type: 'button', class: 'primary' }, '+ New secret');
  const tree = h('nav', { class: 'tree', 'aria-label': 'Secrets' });
  const detail = h('section', { class: 'detail', 'aria-live': 'polite' });
  const el = h('div', { class: 'secrets' }, h('div', { class: 'pane-left' }, newBtn, search, tree), detail);
  const entries = listEntries(snapshot).filter((e) => !isHiddenEntry(e));
  const has = (p: string) => snapshot.hasFile(p);
  const governing = (e: string) => gpgIdFolder(findGpgIdForEntry(has, e));
  let active: string | null = null;
  const fresh = (signal?: AbortSignal) => GitHubSnapshot.load(ctx.client, ctx.config(), { signal });
  const writer = () => new GitHubWriter(ctx.client, ctx.config());

  /** "Readable by Alice, Bob and you (+ the recovery key)" for the folder governing `path`. */
  async function readers(path: string): Promise<HTMLElement> {
    let folder: string;
    try {
      folder = governingFolder(snapshot, path);
    } catch {
      return h('p', { class: 'hint' }, 'No member list covers this location.');
    }
    const people = await members(snapshot, folder);
    return h('p', { class: 'readers' }, h('span', { class: 'hint' }, `Readable by `), namesSentence(people, fpr), h('span', { class: 'hint' }, ` — the members of ${folderLabel(folder)}`));
  }

  void accessibleFolders(snapshot, fpr).then(({ all, mine }) => {
    if (mine.size === 0) {
      newBtn.hidden = true;
      return void detail.replaceChildren(noAccess(ctx, all));
    }
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
      if (!shown.length) tree.append(h('p', { class: 'hint' }, entries.length ? 'No match.' : 'No secrets yet. Add one with “+ New secret”.'));
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
                title: ok ? e.slice(0, -4) : 'You are not a member of this folder',
                'aria-label': e.slice(0, -4),
                onclick: () => void open(e, ok),
              }, ok ? name : `🔒 ${name}`));
            })),
          ),
        );
      }
    };
    search.addEventListener('input', renderTree);
    newBtn.addEventListener('click', () => editor(null));
    renderTree();
    const empty = () =>
      detail.replaceChildren(
        h('div', { class: 'empty' },
          h('p', {}, 'Pick a secret on the left, or add one.'),
          h('p', { class: 'hint' }, `You are a member of ${[...mine].map(folderLabel).join(', ')}.`),
          howSharingWorks()),
      );
    const reopen = memory.selected;
    memory.selected = null;
    if (reopen && entries.includes(reopen)) void open(reopen, canRead(reopen));
    else empty();

    async function open(e: string, ok: boolean) {
      active = e;
      renderTree();
      if (!ok) {
        detail.replaceChildren(h('h3', {}, e.slice(0, -4)), notice('info', `You are not a member of ${folderLabel(governing(e))}, so you cannot open this. Ask one of its admins for access.`), await readers(e));
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
            h('button', { type: 'button', onclick: () => editor(e, password, rest) }, 'Edit'),
            h('button', { type: 'button', class: 'danger', onclick: () => void remove(e) }, 'Delete'),
            h('button', { type: 'button', class: 'ghost', onclick: () => { active = null; renderTree(); empty(); } }, 'Close')),
          rest ? more : '',
          await readers(e),
          status,
        );
        const st = await folderTrustStatus(snapshot, dirname(entryFile(e))).catch(() => null);
        if (st) status.replaceChildren(st.verified ? `✓ This member list is signed by an admin.` : h('span', { class: 'danger-text' }, `⚠ The member list of ${folderLabel(st.folder)} is not verified (${st.reason ?? st.code}). Saving here is disabled.`));
      } catch (err) {
        detail.replaceChildren(notice('danger', errMsg(err)));
        ctx.toast(errMsg(err), true);
      } finally {
        wipe(plain);
      }
    }

    async function remove(e: string) {
      const k = ctx.session.unlockedKey;
      if (!k) return ctx.rerender();
      if (!confirm(`Delete “${e.slice(0, -4)}”? Its old value stays in the git history, so treat it as known to everyone who could read it.`)) return;
      try {
        await deleteSecret(e, { loadSnapshot: fresh, writer: writer(), operatorKey: k });
        await ctx.reload(`Deleted ${e.slice(0, -4)}.`);
      } catch (err) {
        ctx.toast(writeError(err), true);
      }
    }

    /** New secret (path === null) or edit an existing one. */
    function editor(path: string | null, password = '', notes = '') {
      const prev = active;
      active = path;
      renderTree();
      const folders = [...mine].sort();
      const folderSel = h('select', { 'aria-label': 'Folder' }, ...folders.map((f) => h('option', { value: f }, folderLabel(f))));
      const suggested = path ? governing(path) : (prev && mine.has(governing(prev)) ? governing(prev) : folders.find((f) => f !== '') ?? folders[0]!);
      folderSel.value = suggested;
      const name = input({ required: true, placeholder: 'e.g. github or email/smtp', 'aria-label': 'Name' });
      if (path) {
        folderSel.disabled = true;
        const f = governing(path);
        name.value = (f ? path.slice(f.length + 1) : path).slice(0, -4);
        name.readOnly = true;
      }
      const pw = input({ type: 'password', autocomplete: 'new-password', 'aria-label': 'Password', value: password });
      const show = h('button', { type: 'button', class: 'small' }, 'Show');
      show.addEventListener('click', () => {
        pw.type = pw.type === 'password' ? 'text' : 'password';
        show.textContent = pw.type === 'password' ? 'Show' : 'Hide';
      });
      const gen = h('button', { type: 'button', class: 'small' }, 'Generate');
      gen.addEventListener('click', () => {
        pw.value = generatePassword({ length: 20 });
        pw.type = 'text';
        show.textContent = 'Hide';
      });
      const notesIn = h('textarea', { rows: '4', spellcheck: 'false', placeholder: 'Optional: anything else, one per line, e.g.\nuser: deploy-bot\nurl: https://github.com' });
      notesIn.value = notes.replace(/\n$/, '');
      const who = h('div', {});
      const fullPath = () => joinPath(folderSel.value, name.value.trim());
      const updateWho = () => {
        if (!name.value.trim()) return who.replaceChildren(h('p', { class: 'hint' }, 'Only members of the folder can read it.'));
        let p: string;
        try {
          p = secretPath(fullPath());
        } catch (err) {
          return who.replaceChildren(h('p', { class: 'danger-text' }, errMsg(err)));
        }
        void readers(p).then((r) => who.replaceChildren(r));
      };
      name.addEventListener('input', updateWho);
      folderSel.addEventListener('change', updateWho);
      updateWho();
      const f = form(
        async () => {
          const k = ctx.session.unlockedKey;
          if (!k) return ctx.rerender();
          if (!pw.value) throw new G00passError('Enter a password (or press Generate).');
          const target = path ?? secretPath(fullPath());
          const text = pw.value + (notesIn.value.trim() ? '\n' + notesIn.value.replace(/\s+$/, '') + '\n' : '\n');
          const data = new TextEncoder().encode(text);
          try {
            const res = await saveSecret(target, data, { loadSnapshot: fresh, writer: writer(), operatorKey: k, mode: path ? 'edit' : 'create' });
            pw.value = '';
            memory.selected = res.path;
            await ctx.reload(path ? (res.rotated ? `Saved ${res.path.slice(0, -4)}. The new password is recorded as a rotation.` : `Saved ${res.path.slice(0, -4)}.`) : `Added ${res.path.slice(0, -4)}.`);
          } catch (err) {
            throw new G00passError(writeError(err));
          } finally {
            wipe(data);
          }
        },
        (m) => ctx.toast(m, true),
        path ? 'Save changes' : 'Add secret',
        'Encrypting and saving…',
        field('Folder', folderSel, path ? undefined : 'Who can read a secret depends on its folder.'),
        field('Name', name, path ? 'Renaming is not supported yet.' : 'Use / to group, e.g. email/smtp.'),
        h('div', { class: 'field' }, h('label', { class: 'field-label-wrap' }, h('span', { class: 'field-label' }, 'Password'), h('div', { class: 'pw-row' }, pw, show, gen))),
        field('Notes', notesIn),
        who,
      );
      detail.replaceChildren(
        h('h3', {}, path ? `Edit ${path.slice(0, -4)}` : 'New secret'),
        f,
        h('button', { type: 'button', class: 'ghost small', onclick: () => (path ? void open(path, true) : (active = null, renderTree(), empty())) }, 'Cancel'),
      );
      (path ? pw : name).focus();
    }
  });
  return el;
}

/** Short explainer of the sharing model, in plain words. */
export function howSharingWorks(): HTMLElement {
  return help(
    'How does sharing work?',
    h('ul', { class: 'explain' },
      h('li', {}, h('b', {}, 'Everyone has a personal key'), ', kept in their browser behind their passphrase.'),
      h('li', {}, h('b', {}, 'Each folder has a member list.'), ' A secret saved in a folder is locked so that only its members’ keys can open it.'),
      h('li', {}, h('b', {}, 'Giving someone access'), ' = an admin approves their request. The app adds their key to the folder and re-locks its secrets so they can open them too.'),
      h('li', {}, h('b', {}, 'Removing someone'), ' re-locks everything without them. Change the passwords they saw: the app lists them.'),
      h('li', {}, h('b', {}, 'Names'), ' come from people’s keys and can be faked, so when it matters you compare the key code (fingerprint) with the person directly.')),
  );
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
