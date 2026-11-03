import {
  allFolderTrustStatus,
  dirname,
  entryFile,
  evaluateRootTrust,
  folderTrustStatus,
  getPinnedAnchors,
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
  if (st.verified) return 'verified: recipients signed by an authorized admin';
  switch (st.code) {
    case 'signature-missing':
      return 'NOT verified: recipients are not signed by an admin. Writing is disabled.';
    case 'unknown-signer':
    case 'signature-invalid':
      return `NOT verified: recipient list was changed by an unauthorized key or the signature is invalid (${st.reason ?? ''}). Writing is disabled.`;
    case 'anchor-mismatch':
      return 'NOT verified: root recipients do not match your pinned global admins. Writing is disabled.';
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

  async function renderSettings(repo: GitHubRepo, onChange: () => void) {
    clear(settings);
    settings.hidden = false;
    const pinned = getPinnedAnchors(repo);
    settings.append(h('h2', {}, 'Pinned global admins (trust anchors)'));
    if (!pinned) {
      settings.append(h('p', { class: 'hint' }, `None pinned for ${storeIdOf(repo)}.`));
      return;
    }
    settings.append(
      h('p', { class: 'hint' }, `${storeIdOf(repo)} · ${pinned.source} · ${pinned.pinnedAt}`),
      h('ul', { class: 'fprs' }, ...pinned.anchors.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))),
      h('button', {
        class: 'danger',
        onclick: () => {
          if (!confirm('Forget the pinned global admins for this store? Writing stays disabled until you pin again after comparing fingerprints with your admin.')) return;
          resetAnchors(repo);
          opts.setStatus('Pinned anchors reset.');
          onChange();
        },
      }, 'Reset pinned anchors'),
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
      h('p', { class: 'banner warn' }, 'This device has not pinned the global admins of this store yet. Writing is disabled until you do.'),
      h('p', {}, 'Global admins listed in the root .gpg-id. Compare EVERY fingerprint with your admin out of band (in person, phone, or a channel you already trust). Names come from the repository and prove nothing.'),
      h('ul', { class: 'fprs' }, ...items),
      h('label', { class: 'inline' }, ok, 'I compared these fingerprints with my admin and they match.'),
      h('button', {
        onclick: () => {
          if (!ok.checked) {
            opts.setStatus('Confirm that you compared the fingerprints first.', true);
            return;
          }
          pinAnchors(repo, fprs, 'first-use');
          opts.setStatus('Global admins pinned.');
          onChange();
        },
      }, 'Pin these global admins'),
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
    card.append(h('h2', {}, 'Recipient trust'));
    if (!root.ok) {
      if (!root.pinned) {
        await renderPinPrompt(snapshot, repo, root, rerender);
      } else {
        card.append(
          h('p', { class: 'banner danger', role: 'alert' },
            `Root recipient list is NOT trusted: ${root.reason}. Writing is disabled in every folder. Do not ignore this: someone may be trying to add their key.`),
        );
        if (root.added.length) card.append(h('p', {}, 'Not pinned but listed in the root .gpg-id:'), h('ul', { class: 'fprs' }, ...root.added.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))));
        if (root.removed.length) card.append(h('p', {}, 'Pinned but missing from the root .gpg-id:'), h('ul', { class: 'fprs' }, ...root.removed.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))));
      }
    } else if (root.rolledOver) {
      card.append(h('p', { class: 'banner warn' }, `Global admins changed (signed by ${formatFingerprint(root.signer)}). Pinned anchors were updated; check them in the settings below.`));
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
