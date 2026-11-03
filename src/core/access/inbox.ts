import { GPG_ID, joinPath } from '../paths';
import type { IssueSummary } from '../github/issues';
import { type ParseErrorCode, type ParsedAccessRequest, REQUEST_MARKER, parseAccessRequest } from '../requests/parse';
import type { StoreSnapshot } from '../store';
import { checkFolderAdmin } from '../admins';
import { isFolderRecipient } from './folders';
import { type RecipientChangePlan, RecipientChangeError, planFolderRecipientChange } from './recipients';

export interface InboxItem {
  issue: IssueSummary;
  request: ParsedAccessRequest;
  /** The exact before → after recipient change, computed on the inbox snapshot (show it; approve its digest). */
  plan: RecipientChangePlan;
}
/** Valid request, operator is an admin recipient, but the folder must not be re-signed as it is. */
export interface BlockedInboxItem {
  issue: IssueSummary;
  request: ParsedAccessRequest;
  code: 'folder-not-verified' | 'invalid-change' | 'not-recipient' | 'plan-changed';
  reason: string;
}
export interface InvalidInboxItem {
  issue: IssueSummary;
  code: ParseErrorCode | 'no-such-folder' | 'already-recipient';
  message: string;
}
export interface Inbox {
  /** Valid requests the operator can approve or deny. */
  actionable: InboxItem[];
  /** Valid requests the operator would administer, but NOT approvable now (e.g. the folder's current .gpg-id does not verify); shown with the reason. */
  blocked: BlockedInboxItem[];
  /** Marked as requests but failed verification; shown with the reason, never approvable. */
  invalid: InvalidInboxItem[];
  /** Valid requests for folders the operator cannot act on (not shown). */
  hidden: number;
  /** Why each hidden request is hidden (verified-admin check result), for display. */
  hiddenReasons: { issue: IssueSummary; folder: string; reason: string }[];
}

/**
 * Classify open issues for the operator. Issue metadata (author, labels) is
 * ignored; only the signed body counts. Unrelated issues (no marker) are
 * skipped silently.
 */
export async function buildInbox(opts: {
  issues: readonly IssueSummary[];
  snapshot: StoreSnapshot;
  store: { repo: string; storeRoot?: string };
  operatorFingerprint: string;
  now?: Date;
}): Promise<Inbox> {
  const inbox: Inbox = { actionable: [], blocked: [], invalid: [], hidden: 0, hiddenReasons: [] };
  const { snapshot, operatorFingerprint } = opts;
  for (const issue of opts.issues) {
    if (issue.state !== 'open' || !issue.body?.includes(REQUEST_MARKER)) continue;
    const res = await parseAccessRequest(issue.body, { ...opts.store, now: opts.now });
    if (!res.ok) {
      inbox.invalid.push({ issue, code: res.code, message: res.message });
      continue;
    }
    const req = res.request;
    if (!snapshot.hasFile(joinPath(req.folder, GPG_ID))) {
      inbox.invalid.push({ issue, code: 'no-such-folder', message: 'The requested folder has no .gpg-id of its own' });
    } else if (await isFolderRecipient(snapshot, req.folder, req.fingerprint)) {
      inbox.invalid.push({ issue, code: 'already-recipient', message: 'Requester is already a recipient of this folder' });
    } else {
      const recipient = await isFolderRecipient(snapshot, req.folder, operatorFingerprint);
      const admin = await checkFolderAdmin(snapshot, req.folder, operatorFingerprint);
      if (recipient && admin.admin) {
        try {
          const plan = await planFolderRecipientChange(snapshot, req.folder, { add: [{ fingerprint: req.fingerprint, publicKey: req.publicKey }] }, { operatorFingerprint });
          inbox.actionable.push({ issue, request: req, plan });
        } catch (e) {
          if (!(e instanceof RecipientChangeError)) throw e;
          inbox.blocked.push({ issue, request: req, code: e.code, reason: e.message });
        }
      } else {
        inbox.hidden++;
        inbox.hiddenReasons.push({
          issue,
          folder: req.folder,
          reason: admin.admin ? 'you are not a recipient of this folder' : admin.reason,
        });
      }
    }
  }
  return inbox;
}
