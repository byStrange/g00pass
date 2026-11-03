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
  formatFingerprint,
  joinPath,
  memberAccessElsewhere,
  normalizePath,
  parsePublicKey,
  planCreateSubfolder,
  planRemoveSubfolder,
  previewRemoval,
  readRotation,
  removeMember,
  removeSubfolder,
  rotationChecklist,
  sanitizeDisplayText,
  type GitHubRepo,
  type MemberChecklist,
  type StoreSnapshot,
} from '../core';
import { clear, h } from './dom';
import { fprList, renderPlan } from './plan';
import { type Session, copyWithAutoClear } from './session';

export interface FoldersDeps {
  client: GitHubClient;
  getConfig: () => GitHubRepo;
  getSnapshot: () => StoreSnapshot | null;
  session: Session;
  setStatus: (text: string, isError?: boolean) => void;
  /** Store changed (reload). */
  onChanged: () => void;
}

const errMsg = (e: unknown) => (e instanceof G00passError ? e.message : 'Unexpected error');
const label = (f: string) => (f ? `${f}/` : '/ (root)');

async function userIdsOf(snapshot: StoreSnapshot, fpr: string): Promise<string> {
  try {
    const data = await snapshot.readFile(`.public-keys/${fpr}`);
    const keys = data ? await parsePublicKey(data, fpr) : [];
    return keys.length === 1 ? keys[0]!.getUserIDs().slice(0, 3).map((u) => sanitizeDisplayText(u, 200)).join(', ') : '(no key file)';
  } catch {
    return '(unreadable key file)';
  }
}

/**
 * Folder administration (Phase 2): remove member + rotation checklist,
 * create / remove sub-folder. Every action shows the exact plan computed by
 * the core, requires the operator to confirm it, and the core recomputes
 * the plan on the commit base and refuses if its digest changed.
 */
export function mountFolders(deps: FoldersDeps): { el: HTMLElement; refresh: () => void } {
  const select = h('select', { 'aria-label': 'Folder' });
  const body = h('div', { class: 'folder-admin' });
  const el = h(
    'section',
    { class: 'card folders-card' },
    h('h2', {}, 'Manage folder'),
    h('p', { class: 'hint' }, 'Remove members, track rotations, create or remove sub-folders with their own recipients. Needs your unlocked key; you must be an admin and a recipient of the folder.'),
    h('div', { class: 'row' }, select, h('button', { type: 'button', onclick: () => void show() }, 'Open')),
    body,
  );

  const fresh = (signal?: AbortSignal) => GitHubSnapshot.load(deps.client, deps.getConfig(), { signal });
  const writer = () => new GitHubWriter(deps.client, deps.getConfig());

  function refresh() {
    const s = deps.getSnapshot();
    const cur = select.value;
    clear(select);
    clear(body);
    if (!s) return;
    const folders = s.listFiles().filter((p) => p === '.gpg-id' || p.endsWith('/.gpg-id')).map(dirname).sort();
    for (const f of folders) select.append(h('option', { value: f }, label(f)));
    if (folders.includes(cur)) select.value = cur;
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
      wrap.append(h('p', { class: 'hint' }, 'Rotation checklist: nothing open (no removed member can still have a current secret of this folder).'));
      return wrap;
    }
    for (const m of lists) {
      const boxes = m.open.map((i) => ({ i, box: h('input', { type: 'checkbox' }) }));
      const mark = h('button', { type: 'button' }, 'Mark selected as rotated');
      mark.addEventListener('click', async () => {
        const key = deps.session.unlockedKey;
        const picked = boxes.filter((b) => b.box.checked).map((b) => b.i.path);
        if (!key || !picked.length) return deps.setStatus(key ? 'Select the entries you rotated at their source.' : 'Unlock your key first.', true);
        try {
          await commitMarkRotated({ snapshot: await fresh(), writer: writer(), folder, entries: picked, operatorKey: key });
          deps.setStatus(`Marked ${picked.length} entr${picked.length === 1 ? 'y' : 'ies'} as rotated.`);
          deps.onChanged();
          void show();
        } catch (e) {
          deps.setStatus(errMsg(e), true);
        }
      });
      wrap.append(
        h('h3', {}, `Rotate after removing ${m.name ?? ''} `, h('span', { class: 'mono' }, formatFingerprint(m.fingerprint))),
        h('p', { class: 'hint' }, `Removed ${m.removedAt}${m.addedAt ? `, added ${m.addedAt}` : ''}. ${m.open.length} secret(s) they could read are not rotated yet. Change each one at its source (the real credential), then mark it here.`),
        h('ul', { class: 'fprs' }, ...boxes.map(({ i, box }) => h('li', {}, h('label', { class: 'inline' }, box, h('span', { class: 'mono' }, i.path.slice(0, -4)), h('span', { class: 'hint' }, ` last rotated: ${i.rotatedAt ?? (i.createdAt ? 'never' : 'unknown')}`))))),
        m.done.length ? h('p', { class: 'hint' }, `Already rotated since: ${m.done.map((d) => d.path.slice(0, -4)).join(', ')}`) : '',
        h('ul', { class: 'hint' }, ...m.notes.map((n) => h('li', {}, n))),
        mark,
      );
    }
    return wrap;
  }

  async function show() {
    const folder = select.value;
    const snapshot = deps.getSnapshot();
    clear(body);
    if (!snapshot || !snapshot.hasFile(joinPath(folder, '.gpg-id'))) return;
    const key = deps.session.unlockedKey;
    const op = key?.getFingerprint().toUpperCase() ?? null;
    const escrow = await escrowRecipientIds(snapshot);

    // ---- members ----
    const members = await folderRecipientFingerprints(snapshot, folder);
    const list = h('ul', { class: 'fprs' });
    for (const fpr of members) {
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
              deps.setStatus(
                `Removed ${formatFingerprint(fpr)} from ${label(folder)}.` +
                  (elsewhere.length ? ` Still has access in: ${elsewhere.map((e) => `${label(e.folder)}${e.recipient ? '' : ' (admin only)'}`).join(', ')} — remove them there too.` : ''),
              );
              deps.onChanged();
              void show();
            }, true),
          );
        } catch (e) {
          deps.setStatus(errMsg(e), true);
        }
      });
      list.append(h('li', {}, h('span', { class: 'mono' }, formatFingerprint(fpr)), ' ', h('span', { class: 'hint uid', dir: 'auto' }, await userIdsOf(snapshot, fpr)), ' ', fpr === op ? h('span', { class: 'badge' }, 'you') : rm));
    }
    body.append(h('h3', {}, `Members of ${label(folder)}`), list, escrow.length ? h('p', { class: 'hint' }, 'The escrow (recovery) key is always a recipient and cannot be removed.') : '');

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
    const picks = members.map((m) => ({ m, box: h('input', { type: 'checkbox', checked: m === op }) }));
    const extra = h('textarea', { rows: '2', spellcheck: 'false', placeholder: 'More recipients: full fingerprints (key must be in .public-keys), one per line' });
    const createBtn = h('button', { type: 'button', disabled: !key }, 'Review new sub-folder…');
    const createForm = h(
      'details',
      {},
      h('summary', {}, 'Create a sub-folder with its own recipients'),
      h('p', { class: 'hint' }, `One commit: ${label(folder)} declares the new boundary in its signature, the sub-folder's .gpg-id is signed, and entries already under it are re-encrypted to the new recipients.`),
      name,
      h('ul', { class: 'fprs' }, ...picks.map(({ m, box }) => h('li', {}, h('label', { class: 'inline' }, box, h('span', { class: 'mono' }, formatFingerprint(m)))))),
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
        const view = h(
          'div',
          { class: 'plan' },
          h('p', {}, `Create ${label(plan.folder)} below ${label(plan.parent)}.`),
          fprList('Recipients (plus escrow)', plan.recipients, 'added'),
          plan.entries.length ? h('p', {}, `${plan.entries.length} existing entr${plan.entries.length === 1 ? 'y moves' : 'ies move'} to the new recipients: ${plan.entries.map((e) => e.slice(0, -4)).join(', ')}`) : null,
          plan.losingAccess.length ? fprList('These recipients of the parent lose access to those entries (they are put on the rotation checklist)', plan.losingAccess, 'removed') : null,
        );
        createForm.append(
          confirmBox(view, 'Create sub-folder', async () => {
            await createSubfolder(plan.folder, recips, { loadSnapshot: fresh, writer: writer(), operatorKey: k, approvedPlanDigest: plan.digest });
            deps.setStatus(`Created ${label(plan.folder)}.`);
            deps.onChanged();
          }),
        );
      } catch (e) {
        deps.setStatus(errMsg(e), true);
      }
    });
    body.append(createForm);

    // ---- invite ----
    body.append(inviteForm(folder));

    // ---- remove sub-folder (merge into parent) ----
    if (folder !== '') {
      const rmBtn = h('button', { type: 'button', class: 'danger', disabled: !key }, 'Review removal…');
      const rmForm = h(
        'details',
        {},
        h('summary', {}, `Remove ${label(folder)} as a separate folder (merge into its parent)`),
        h('p', { class: 'hint' }, "Its entries are re-encrypted to the parent folder's recipients, its .gpg-id is deleted, and the parent's signature explicitly records the removal."),
        rmBtn,
      );
      rmBtn.addEventListener('click', async () => {
        const k = deps.session.unlockedKey;
        if (!k) return deps.setStatus('Unlock your key first.', true);
        try {
          const plan = await planRemoveSubfolder(await fresh(), folder, { operatorFingerprint: k.getFingerprint().toUpperCase() });
          const view = h(
            'div',
            { class: 'plan' },
            h('p', {}, `${plan.entries.length} entr${plan.entries.length === 1 ? 'y' : 'ies'} of ${label(plan.folder)} will be readable by the recipients of ${label(plan.parent)}.`),
            fprList('Recipients before', plan.before),
            fprList('Recipients after', plan.after),
            plan.gainingAccess.length ? fprList('GAIN access to these secrets', plan.gainingAccess, 'added') : null,
          );
          rmForm.append(
            confirmBox(view, 'Remove sub-folder boundary', async () => {
              await removeSubfolder(folder, { loadSnapshot: fresh, writer: writer(), operatorKey: k, approvedPlanDigest: plan.digest });
              deps.setStatus(`${label(folder)} merged into ${label(plan.parent)}.`);
              deps.onChanged();
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
          h('p', { class: 'hint' }, `Invite ${inv.id} (${inv.record.role} on ${label(folder)}) expires ${inv.record.expiresAt}. Tell the newcomer the global admin fingerprints separately so they can check them.`),
        );
        deps.onChanged();
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
