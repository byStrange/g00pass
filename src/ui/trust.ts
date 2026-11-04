import {
  allFolderTrustStatus,
  dirname,
  entryFile,
  evaluateRootTrust,
  folderTrustStatus,
  G00passError,
  getPinnedAnchors,
  normalizeFingerprints,
  parsePublicKey,
  pinAnchors,
  resetAnchors,
  storeIdOf,
  type FolderTrustStatus,
  type GitHubRepo,
  type RootTrust,
  type StoreSnapshot,
} from '../core';
import { clear, h } from './dom';

/** "3F2A9C0D…" -> "3F2A 9C0D …" (always the FULL fingerprint). */
export function formatFingerprint(fpr: string): string {
  return fpr.replace(/(.{4})(?=.)/g, '$1 ');
}

const folderName = (f: string) => (f ? `${f}/` : '/ (root)');

function describe(st: FolderTrustStatus): string {
  if (st.verified) {
    const gone = st.warnings.filter((w) => w.startsWith('boundary-vanished:')).map((w) => w.slice('boundary-vanished:'.length) + '/');
    return gone.length
      ? `verified, but the member list of sub-folder(s) ${gone.join(', ')} was DELETED; saving there and changing members here are disabled`
      : '✓ member list signed by an admin';
  }
  switch (st.code) {
    case 'signature-missing':
      return 'NOT verified: the member list is not signed by an admin. Saving is disabled.';
    case 'unknown-signer':
    case 'signature-invalid':
      return `NOT verified: the member list was changed by someone who is not an admin, or its signature is invalid (${st.reason ?? ''}). Saving is disabled.`;
    case 'anchor-mismatch':
      return 'NOT verified: the store’s admins do not match the admins this browser trusts. Saving is disabled.';
    case 'boundary-vanished':
      return `NOT verified: a sub-folder’s member list was deleted (${st.reason ?? ''}). Saving is disabled so its secrets are not shared with the parent folder’s members.`;
    case 'boundary-undeclared':
      return `NOT verified: the parent folder’s admin never approved this folder’s member list (${st.reason ?? ''}). Saving is disabled.`;
    default:
      return `NOT verified: ${st.reason ?? 'unknown reason'}. Writing is disabled.`;
  }
}

async function claimedUserIds(snapshot: StoreSnapshot, fpr: string): Promise<string> {
  try {
    const data = await snapshot.readFile(`.public-keys/${fpr}`);
    if (!data) return '(no key file)';
    const keys = await parsePublicKey(data, fpr);
    return keys.length === 1 && keys[0]!.getFingerprint().toUpperCase() === fpr ? keys[0]!.getUserIDs().join(', ') : '(key file does not match)';
  } catch {
    return '(unreadable key file)';
  }
}

/**
 * Trust UI: first-connect anchor pinning, root mismatch banner, per-folder
 * verified/unverified status, pinned-anchor settings. Decisions all come from
 * the core trust policy; this only displays them.
 */
export function createTrustPanel(opts: { setStatus: (t: string, isError?: boolean) => void }) {
  const card = h('section', { class: 'card trust', hidden: true });
  const settings = h('section', { class: 'card', hidden: true });
  let generation = 0;

  /** Manual pin (store-layout.md §Trust anchors, source 'manual'): full fingerprints typed/pasted from a trusted channel. */
  function manualPinForm(repo: GitHubRepo, onChange: () => void): HTMLElement {
    const ta = h('textarea', { rows: '3', spellcheck: 'false', placeholder: 'Full key fingerprints of the admins, one per line' });
    const ok = h('input', { type: 'checkbox' });
    return h(
      'details',
      {},
      h('summary', {}, 'Set trusted admins manually'),
      h('p', { class: 'hint' }, 'Paste the FULL key fingerprints your admin gave you through a channel you already trust. This replaces the trusted admins for this store.'),
      ta,
      h('label', { class: 'inline' }, ok, 'These fingerprints come from my admin through a trusted channel.'),
      h('button', {
        type: 'button',
        onclick: () => {
          if (!ok.checked) return opts.setStatus('Confirm where the fingerprints come from first.', true);
          try {
            const fprs = normalizeFingerprints(ta.value.split(/[\n,;]+/).map((l) => l.replace(/\s+/g, '')).filter(Boolean));
            if (!fprs.length) return opts.setStatus('Enter at least one full fingerprint.', true);
            if (!confirm(`Trust these ${fprs.length} admin(s)?\n\n${fprs.map(formatFingerprint).join('\n')}`)) return;
            pinAnchors(repo, fprs, 'manual');
            ta.value = '';
            opts.setStatus('Trusted admins saved.');
            onChange();
          } catch (e) {
            opts.setStatus(e instanceof G00passError ? e.message : 'Invalid fingerprints.', true);
          }
        },
      }, 'Pin these fingerprints'),
    );
  }

  async function renderSettings(repo: GitHubRepo, onChange: () => void) {
    clear(settings);
    settings.hidden = false;
    const pinned = getPinnedAnchors(repo);
    settings.append(h('h2', {}, 'Trusted admins'));
    if (!pinned) {
      settings.append(h('p', { class: 'hint' }, `No trusted admins yet for ${storeIdOf(repo)}.`), manualPinForm(repo, onChange));
      return;
    }
    settings.append(
      h('p', { class: 'hint' }, `${storeIdOf(repo)} · confirmed via ${({ 'first-use': 'first connect', invite: 'invite', manual: 'manual entry', rollover: 'admin change' } as Record<string, string>)[pinned.source] ?? pinned.source} · ${new Date(pinned.pinnedAt).toLocaleString()}`),
      h('ul', { class: 'fprs' }, ...pinned.anchors.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))),
      h('button', {
        class: 'danger',
        onclick: () => {
          if (!confirm('Forget the trusted admins for this store? Saving stays disabled until you confirm the admins again (compare their fingerprints with them first).')) return;
          resetAnchors(repo);
          opts.setStatus('Trusted admins forgotten.');
          onChange();
        },
      }, 'Forget trusted admins'),
      manualPinForm(repo, onChange),
    );
  }

  async function renderPinPrompt(snapshot: StoreSnapshot, repo: GitHubRepo, root: Extract<RootTrust, { ok: false }>, onChange: () => void) {
    const fprs = root.root?.admins ?? [];
    if (!fprs.length) {
      card.append(h('p', { class: 'banner danger' }, `Cannot pin: ${root.reason}`));
      return;
    }
    const ok = h('input', { type: 'checkbox' });
    const items = await Promise.all(
      fprs.map(async (f) => h('li', {}, h('span', { class: 'mono' }, formatFingerprint(f)), h('span', { class: 'hint' }, ` claimed: ${await claimedUserIds(snapshot, f)}`))),
    );
    card.append(
      h('p', { class: 'banner warn' }, 'This browser has not confirmed the admins of this store yet. Saving is disabled until you do.'),
      h('p', {}, 'Admins listed by the store. Compare EVERY fingerprint with your admin out of band (in person, phone, or a channel you already trust). Names come from the repository and prove nothing.'),
      h('ul', { class: 'fprs' }, ...items),
      h('label', { class: 'inline' }, ok, 'I compared these fingerprints with my admin and they match.'),
      h('button', {
        onclick: () => {
          if (!ok.checked) {
            opts.setStatus('Confirm that you compared the fingerprints first.', true);
            return;
          }
          pinAnchors(repo, fprs, 'first-use');
          opts.setStatus('Admins confirmed.');
          onChange();
        },
      }, 'Trust these admins'),
    );
  }

  async function refresh(snapshot: StoreSnapshot | null, repo: GitHubRepo) {
    const gen = ++generation;
    const rerender = () => void refresh(snapshot, repo);
    if (!snapshot) {
      card.hidden = true;
      settings.hidden = true;
      return;
    }
    const root = await evaluateRootTrust(snapshot);
    const statuses = await allFolderTrustStatus(snapshot);
    if (gen !== generation) return;
    clear(card);
    card.hidden = false;
    card.append(h('h2', {}, 'Folder status'));
    if (!root.ok) {
      if (!root.pinned) {
        await renderPinPrompt(snapshot, repo, root, rerender);
      } else {
        card.append(
          h('p', { class: 'banner danger', role: 'alert' },
            `The store’s admin list is NOT trusted: ${root.reason}. Saving is disabled in every folder. Do not ignore this: someone may be trying to add their key.`),
        );
        if (root.added.length) card.append(h('p', {}, 'Not pinned but listed in the root .gpg-id:'), h('ul', { class: 'fprs' }, ...root.added.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))));
        if (root.removed.length) card.append(h('p', {}, 'Pinned but missing from the root .gpg-id:'), h('ul', { class: 'fprs' }, ...root.removed.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))));
      }
    } else if (root.rolledOver) {
      card.append(h('p', { class: 'banner warn' }, `The admins changed (approved by an admin, key ${formatFingerprint(root.signer)}). The trusted admins were updated; check them below.`));
    }
    card.append(
      h('ul', { class: 'folders' }, ...statuses.map((s) =>
        h('li', { class: s.verified ? 'ok' : 'bad' }, h('span', { class: 'mono' }, folderName(s.folder)), ' ', describe(s)))),
    );
    await renderSettings(repo, rerender);
  }

  /** One-line status of the recipients governing `entry` (shown in the entry view). */
  async function entryStatus(snapshot: StoreSnapshot, entry: string): Promise<HTMLElement> {
    const st = await folderTrustStatus(snapshot, dirname(entryFile(entry)));
    return h('p', { class: st.verified ? 'hint trust-ok' : 'hint trust-bad' }, `Recipients of ${folderName(st.folder)}: ${describe(st)}`);
  }

  return { card, settings, refresh, entryStatus };
}
