import {
  G00passError,
  GitHubClient,
  GitHubSnapshot,
  MAX_INVITE_DAYS,
  issueInvite,
  probeInviteToken,
  type RequestRole,
  GitHubWriter,
  commitMarkRotated,
  createSubfolder,
  dirname,
  escrowRecipientIds,
  folderRecipientFingerprints,
  joinPath,
  memberAccessElsewhere,
  normalizePath,
  planCreateSubfolder,
  planRemoveSubfolder,
  previewRemoval,
  readRotation,
  removeMember,
  removeSubfolder,
  rotationChecklist,
  type GitHubRepo,
  type MemberChecklist,
  type StoreSnapshot,
} from '../core';
import { clear, h } from './dom';
import { fprList, renderPlan } from './plan';
import { avatarStack, members, person, personBlock, shortFpr, tile } from './people';
import { icon } from './icons';
import { type Session, copyWithAutoClear } from './session';

export interface FoldersDeps {
  client: GitHubClient;
  getConfig: () => GitHubRepo;
  getSnapshot: () => StoreSnapshot | null;
  session: Session;
  setStatus: (text: string, isError?: boolean) => void;
  /** Store changed: reload, keeping `note` (the action's result) visible. */
  onChanged: (note?: string) => void;
  /** Remembers the opened folder across re-renders (owned by the app). */
  memory?: { folder: string | null };
}

const errMsg = (e: unknown) => (e instanceof G00passError ? e.message : 'Unexpected error');
const label = (f: string) => (f ? `${f}/` : '/ (root)');

/**
 * Folder administration (Phase 2): remove member + rotation checklist,
 * create / remove sub-folder. Every action shows the exact plan computed by
 * the core, requires the operator to confirm it, and the core recomputes
 * the plan on the commit base and refuses if its digest changed.
 */
export function mountFolders(deps: FoldersDeps): { el: HTMLElement; refresh: () => void } {
  const list = h('div', { class: 'folder-list', role: 'list', 'aria-label': 'Folders' });
  const body = h('div', { class: 'folder-admin' });
  const el = h(
    'section',
    { class: 'panel folders-card' },
    h('div', { class: 'panel-head' }, h('h3', {}, 'Folders')),
    h('p', { class: 'hint' }, 'Pick a folder to see who has access, invite people, remove them, or split it into sub-folders.'),
    h('div', { class: 'folders-layout' }, list, body),
  );
  let current = '';

  const fresh = (signal?: AbortSignal) => GitHubSnapshot.load(deps.client, deps.getConfig(), { signal });
  const writer = () => new GitHubWriter(deps.client, deps.getConfig());

  /** Folder currently opened (re-opened after a reload so results stay visible). */
  const memory = deps.memory ?? { folder: null };
  let opened: string | null = memory.folder;

  function refresh() {
    const s = deps.getSnapshot();
    clear(list);
    clear(body);
    if (!s) return;
    const folders = s.listFiles().filter((p) => p === '.gpg-id' || p.endsWith('/.gpg-id')).map(dirname).sort();
    for (const f of folders) {
      const depth = f ? f.split('/').length : 0;
      const meta = h('span', { class: 'folder-meta' });
      list.append(h('button', {
        type: 'button',
        role: 'listitem',
        class: `folder-btn depth-${Math.min(depth, 4)}`,
        'aria-pressed': String(opened === f),
        onclick: () => {
          current = f;
          for (const b of list.children) b.setAttribute('aria-pressed', String(b === list.children[folders.indexOf(f)]));
          void show();
        },
      }, icon('folder', { size: 16 }), h('span', { class: 'folder-name' }, label(f)), meta));
      void members(s, f).then((ps) => meta.replaceChildren(avatarStack(ps.filter((p) => !p.escrow), 3)));
    }
    if (opened !== null && folders.includes(opened)) {
      current = opened;
      void show();
    } else {
      opened = null;
      body.append(h('div', { class: 'empty' }, h('div', { class: 'empty-icon' }, icon('folder', { size: 28 })), h('h3', {}, 'Pick a folder'), h('p', { class: 'hint' }, 'See who can open it, invite someone, or remove a member.')));
    }
  }

  /** A confirm box: plan view, review checkbox, action button. */
  function confirmBox(planView: HTMLElement, action: string, run: (progress: HTMLElement) => Promise<void>, danger = false): HTMLElement {
    const reviewed = h('input', { type: 'checkbox' });
    const btn = h('button', { type: 'button', class: danger ? 'danger' : 'primary', disabled: true }, action);
    const progress = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
    reviewed.addEventListener('change', () => (btn.disabled = !reviewed.checked));
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      reviewed.disabled = true;
      try {
        await run(progress);
      } catch (e) {
        deps.setStatus(errMsg(e), true);
        reviewed.disabled = false;
        btn.disabled = !reviewed.checked;
      }
    });
    return h('div', { class: 'request' }, planView, h('label', { class: 'inline' }, reviewed, 'I reviewed this exact change and approve it.'), h('div', { class: 'row' }, btn), progress);
  }

  function checklistView(folder: string, lists: readonly MemberChecklist[]): HTMLElement {
    const wrap = h('div', { class: 'checklist' });
    if (!lists.length) {
      wrap.append(h('p', { class: 'hint' }, 'Password checklist: nothing to change (no removed member knows a current password of this folder).'));
      return wrap;
    }
    for (const m of lists) {
      const boxes = m.open.map((i) => ({ i, box: h('input', { type: 'checkbox' }) }));
      const mark = h('button', { type: 'button' }, 'I changed the ticked ones');
      mark.addEventListener('click', async () => {
        const key = deps.session.unlockedKey;
        const picked = boxes.filter((b) => b.box.checked).map((b) => b.i.path);
        if (!key || !picked.length) return deps.setStatus(key ? 'Select the entries you rotated at their source.' : 'Unlock your key first.', true);
        try {
          await commitMarkRotated({ snapshot: await fresh(), writer: writer(), folder, entries: picked, operatorKey: key });
          deps.onChanged(`Marked ${picked.length} password${picked.length === 1 ? '' : 's'} as changed.`);
        } catch (e) {
          deps.setStatus(errMsg(e), true);
        }
      });
      wrap.append(
        h('h3', {}, `Change these passwords: ${m.name ?? 'a removed member'} could read them`),
        h('p', { class: 'hint' }, `Removed ${new Date(m.removedAt).toLocaleString()} (key …${shortFpr(m.fingerprint)}). ${m.open.length} secret(s) they could read still have the same password. Change each one where it is used (the real account or service), save the new value here, or tick it if you changed it elsewhere.`),
        h('ul', { class: 'fprs' }, ...boxes.map(({ i, box }) => h('li', {}, h('label', { class: 'inline' }, box, h('span', { class: 'mono' }, i.path.slice(0, -4)), h('span', { class: 'hint' }, ` last changed: ${i.rotatedAt ? new Date(i.rotatedAt).toLocaleDateString() : i.createdAt ? 'never' : 'unknown'}`))))),
        m.done.length ? h('p', { class: 'hint' }, `Already rotated since: ${m.done.map((d) => d.path.slice(0, -4)).join(', ')}`) : '',
        h('ul', { class: 'hint' }, ...m.notes.map((n) => h('li', {}, n))),
        mark,
      );
    }
    return wrap;
  }

  /** fingerprint -> display name, for plan views. */
  async function namesFor(snapshot: StoreSnapshot, fprs: readonly string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const f of fprs) out.set(f, (await person(snapshot, f)).name);
    return out;
  }

  async function show() {
    const folder = current;
    const snapshot = deps.getSnapshot();
    opened = folder;
    memory.folder = folder;
    clear(body);
    if (!snapshot || !snapshot.hasFile(joinPath(folder, '.gpg-id'))) return;
    const key = deps.session.unlockedKey;
    const op = key?.getFingerprint().toUpperCase() ?? null;
    const escrow = await escrowRecipientIds(snapshot);

    // ---- members ----
    const members_ = await folderRecipientFingerprints(snapshot, folder);
    const list = h('ul', { class: 'members' });
    for (const fpr of members_) {
      const rm = h('button', { type: 'button', class: 'danger', disabled: !key || fpr === op }, 'Remove…');
      rm.addEventListener('click', async () => {
        const k = deps.session.unlockedKey;
        if (!k) return deps.setStatus('Unlock your key first.', true);
        try {
          const s = await fresh();
          const plan = await previewRemoval(s, folder, fpr, k.getFingerprint().toUpperCase());
          const view = h('div', {}, h('p', { class: 'banner warn' }, 'Removing a key does NOT revoke what they already decrypted (and git history keeps the old ciphertext). Rotate every secret on the checklist afterwards.'), renderPlan(plan));
          list.after(
            confirmBox(view, 'Remove member', async (progress) => {
              await removeMember(folder, fpr, {
                loadSnapshot: fresh,
                writer: writer(),
                operatorKey: k,
                approvedPlanDigest: plan.digest,
                onProgress: (p) => (progress.textContent = `${p.phase}: ${p.done}/${p.total}`),
              });
              const after = await fresh();
              const elsewhere = await memberAccessElsewhere(after, fpr, folder);
              const who = (await person(s, fpr)).name;
              deps.onChanged(
                `Removed ${who} from ${label(folder)}. Change the passwords on the checklist below.` +
                  (elsewhere.length ? ` ${who} still has access to: ${elsewhere.map((e) => `${label(e.folder)}${e.recipient ? '' : ' (as admin)'}`).join(', ')} — remove them there too.` : ''),
              );
            }, true),
          );
        } catch (e) {
          deps.setStatus(errMsg(e), true);
        }
      });
      list.append(h('li', { class: 'member' }, personBlock(await person(snapshot, fpr), { me: op }), fpr === op ? '' : rm));
    }
    body.append(h('div', { class: 'folder-head' }, tile(folder || 'root', 'lg'), h('div', {}, h('h2', {}, label(folder)), h('p', { class: 'hint' }, `${members_.length} member${members_.length === 1 ? '' : 's'} can open its secrets`))), h('h3', {}, `Members of ${label(folder)}`), list, escrow.length ? h('p', { class: 'hint' }, 'The recovery key is always a member and cannot be removed.') : '');
    body.append(inviteForm(folder));

    // ---- rotation checklist ----
    if (key) {
      try {
        const doc = await readRotation(snapshot, folder, [key]);
        body.append(checklistView(folder, rotationChecklist(doc, snapshot, { escrow })));
      } catch (e) {
        body.append(h('p', { class: 'hint' }, `Rotation checklist unavailable: ${errMsg(e)}`));
      }
    }

    // ---- create sub-folder ----
    const name = h('input', { placeholder: 'sub-folder name, e.g. prod', autocomplete: 'off', spellcheck: 'false' });
    const picks = members_.map((m) => ({ m, box: h('input', { type: 'checkbox', checked: m === op }) }));
    const pickNames = await namesFor(snapshot, members_);
    const extra = h('textarea', { rows: '2', spellcheck: 'false', placeholder: 'Other people: their full key fingerprint (they must have a key in the store), one per line' });
    const createBtn = h('button', { type: 'button', disabled: !key }, 'Review new sub-folder…');
    const createForm = h(
      'details',
      {},
      h('summary', {}, 'Create a sub-folder with different members'),
      h('p', { class: 'hint' }, `Use this when only some people should see certain secrets, e.g. ${label(folder)}prod for production passwords. Pick who can read it; secrets already in that sub-folder move over to the new members.`),
      name,
      h('p', { class: 'hint' }, 'Who can read it:'),
      h('ul', { class: 'pick-list' }, ...picks.map(({ m, box }) => h('li', {}, h('label', { class: 'inline' }, box, h('b', { class: 'uid', dir: 'auto' }, pickNames.get(m) ?? m), h('span', { class: 'hint mono' }, ` …${shortFpr(m)}`))))),
      extra,
      createBtn,
    );
    createBtn.addEventListener('click', async () => {
      const k = deps.session.unlockedKey;
      if (!k) return deps.setStatus('Unlock your key first.', true);
      try {
        const sub = normalizePath(joinPath(folder, name.value.trim()));
        if (!name.value.trim() || sub === normalizePath(folder)) return deps.setStatus('Enter a sub-folder name.', true);
        const recips = [...picks.filter((p) => p.box.checked).map((p) => p.m), ...extra.value.split(/[\s,;]+/).map((x) => x.trim().toUpperCase()).filter(Boolean)];
        const s = await fresh();
        const plan = await planCreateSubfolder(s, sub, recips, { operatorFingerprint: k.getFingerprint().toUpperCase() });
        const nm = await namesFor(s, [...plan.recipients, ...plan.losingAccess]);
        const view = h(
          'div',
          { class: 'plan' },
          h('p', {}, `Create ${label(plan.folder)} below ${label(plan.parent)}.`),
          fprList('Members (plus the recovery key)', plan.recipients, 'added', nm),
          plan.entries.length ? h('p', {}, `${plan.entries.length} existing secret${plan.entries.length === 1 ? ' moves' : 's move'} to the new members: ${plan.entries.map((e) => e.slice(0, -4)).join(', ')}`) : null,
          plan.losingAccess.length ? fprList('These members of the parent folder lose access to them (they are put on the password checklist)', plan.losingAccess, 'removed', nm) : null,
        );
        createForm.append(
          confirmBox(view, 'Create sub-folder', async () => {
            await createSubfolder(plan.folder, recips, { loadSnapshot: fresh, writer: writer(), operatorKey: k, approvedPlanDigest: plan.digest });
            deps.onChanged(`Created ${label(plan.folder)}.`);
          }),
        );
      } catch (e) {
        deps.setStatus(errMsg(e), true);
      }
    });
    body.append(createForm);

    // ---- remove sub-folder (merge into parent) ----
    if (folder !== '') {
      const rmBtn = h('button', { type: 'button', class: 'danger', disabled: !key }, 'Review merge…');
      const rmForm = h(
        'details',
        {},
        h('summary', {}, `Merge ${label(folder)} back into its parent folder`),
        h('p', { class: 'hint' }, "Its secrets become readable by the parent folder’s members, and its own member list is deleted."),
        rmBtn,
      );
      rmBtn.addEventListener('click', async () => {
        const k = deps.session.unlockedKey;
        if (!k) return deps.setStatus('Unlock your key first.', true);
        try {
          const s = await fresh();
          const plan = await planRemoveSubfolder(s, folder, { operatorFingerprint: k.getFingerprint().toUpperCase() });
          const nm = await namesFor(s, [...plan.before, ...plan.after]);
          const view = h(
            'div',
            { class: 'plan' },
            h('p', {}, `${plan.entries.length} secret${plan.entries.length === 1 ? '' : 's'} of ${label(plan.folder)} will be readable by the members of ${label(plan.parent)}.`),
            fprList('Members before', plan.before, '', nm),
            fprList('Members after', plan.after, '', nm),
            plan.gainingAccess.length ? fprList('These people GAIN access to those secrets', plan.gainingAccess, 'added', nm) : null,
          );
          rmForm.append(
            confirmBox(view, 'Merge into parent', async () => {
              await removeSubfolder(folder, { loadSnapshot: fresh, writer: writer(), operatorKey: k, approvedPlanDigest: plan.digest });
              deps.onChanged(`${label(folder)} merged into ${label(plan.parent)}.`);
            }, true),
          );
        } catch (e) {
          deps.setStatus(errMsg(e), true);
        }
      });
      body.append(rmForm);
    }
  }

  /** Issue an invite (access-requests.md §Admin client): token check, signed record, link shown once. */
  function inviteForm(folder: string): HTMLElement {
    const role = h('select', {}, h('option', { value: 'reader' }, 'reader'), h('option', { value: 'folder-admin' }, 'folder-admin'));
    const days = h('input', { type: 'number', min: '1', max: String(MAX_INVITE_DAYS), value: '7' });
    const note = h('input', { maxlength: '500', autocomplete: 'off', placeholder: 'Note for the record (optional, not secret)' });
    const token = h('input', { type: 'password', autocomplete: 'off', placeholder: 'github_pat_… (Issues: Read and write on the requests repo ONLY)' });
    const out = h('div', {});
    const btn = h('button', { type: 'button' }, 'Check token & create invite');
    const cfg = deps.getConfig();
    const requestsRepo = cfg.requestsRepo?.trim() || `${cfg.owner}/${cfg.repo}`;
    btn.addEventListener('click', async () => {
      const k = deps.session.unlockedKey;
      const t = token.value.trim();
      token.value = '';
      if (!k) return deps.setStatus('Unlock your key first.', true);
      if (!t) return deps.setStatus('Paste the requester token first.', true);
      clear(out);
      try {
        const probe = await probeInviteToken(new GitHubClient({ token: () => t }), deps.getConfig());
        if (!probe.ok) return deps.setStatus(`Token refused: ${probe.reason}`, true);
        const inv = await issueInvite({
          snapshot: await fresh(),
          writer: writer(),
          repo: deps.getConfig(),
          folder,
          role: role.value as RequestRole,
          days: Number(days.value),
          note: note.value,
          token: t,
          appUrl: location.origin + location.pathname,
          operatorKey: k,
        });
        const link = h('textarea', { rows: '3', readonly: true, spellcheck: 'false' });
        link.value = inv.link;
        out.append(
          h('p', { class: 'banner warn' }, 'This link CONTAINS A CREDENTIAL (the requester token). Send it only through a channel you trust, then close this view. It is not stored anywhere.'),
          link,
          h('div', { class: 'row' },
            h('button', { type: 'button', onclick: () => void copyWithAutoClear(inv.link, 60_000, () => deps.setStatus('Clipboard cleared.')).then(() => deps.setStatus('Invite link copied (clipboard clears in 60 s).'), () => deps.setStatus('Clipboard not available.', true)) }, 'Copy link'),
            h('button', { type: 'button', onclick: () => clear(out) }, 'Done (hide link)')),
          h('p', { class: 'hint' }, `Invite ${inv.id} (${inv.record.role} on ${label(folder)}) expires ${inv.record.expiresAt}. Tell the newcomer your key fingerprint separately (in person or on a call) so they can check the invite.`),
        );
        // No reload here: it would re-render this card and hide the link, which is shown only once.
        deps.setStatus('Invite created.');
      } catch (e) {
        deps.setStatus(errMsg(e), true);
      }
    });
    return h(
      'details',
      {},
      h('summary', {}, `Invite someone to ${label(folder)}`),
      h('ol', { class: 'hint' },
        h('li', {}, 'On GitHub: Settings → Developer settings → Fine-grained tokens → Generate new token.'),
        h('li', {}, `Resource owner: the owner of ${requestsRepo}. Repository access: Only select repositories → ${requestsRepo}.`),
        h('li', {}, 'Permissions: Issues: Read and write (Metadata: Read-only is added automatically). Nothing else.'),
        h('li', {}, `Expiration: custom, at most ${MAX_INVITE_DAYS} days. Revoke it after the request is approved.`)),
      requestsRepo === `${cfg.owner}/${cfg.repo}` ? h('p', { class: 'banner warn' }, 'No separate requests repo is configured: the invite token will be able to read and edit every issue of the store repo.') : '',
      h('label', {}, 'Role', role),
      h('label', {}, 'Valid for (days)', days),
      note,
      h('label', {}, 'Requester token (used for the link only, never stored)', token),
      btn,
      out,
    );
  }

  return { el, refresh };
}
