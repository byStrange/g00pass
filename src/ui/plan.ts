import { formatFingerprint, type PlannedRecipient, type RecipientChangePlan } from '../core';
import { h } from './dom';

const nameOf = (uid: string | undefined) => (uid ?? '').replace(/\s*<[^>]*>\s*$/, '').trim();
const tail = (fpr: string) => (fpr.slice(-16).match(/.{4}/g) ?? []).join(' ');

/** Shared rendering of an exact before → after member change (approve / remove): names first, full fingerprint below. */
export function recipientList(title: string, list: readonly PlannedRecipient[], mark: (fpr: string) => string | null): HTMLElement {
  return h(
    'div',
    { class: 'plan-side' },
    h('h4', {}, title),
    h(
      'ul',
      { class: 'people-list' },
      ...list.map((p) => {
        const m = mark(p.fingerprint);
        return h(
          'li',
          { class: m ?? '' },
          h('b', { class: 'uid', dir: 'auto' }, p.escrow ? 'Recovery key' : nameOf(p.userIds[0]) || `Key …${tail(p.fingerprint)}`),
          m ? h('span', { class: `badge ${m}` }, m) : '',
          h('div', { class: 'hint' }, p.userIds[0] && !p.escrow ? h('span', { class: 'uid', dir: 'auto' }, `${p.userIds[0]} · `) : '', h('span', { class: 'mono', dir: 'ltr' }, formatFingerprint(p.fingerprint))),
        );
      }),
    ),
  );
}

/** Fingerprints with optional names (`names`: fingerprint -> display name). */
export function fprList(title: string, fprs: readonly string[] | null, cls = '', names?: ReadonlyMap<string, string>): HTMLElement {
  return h(
    'div',
    { class: 'plan-side' },
    h('h4', {}, title),
    fprs && fprs.length
      ? h('ul', { class: 'people-list' }, ...fprs.map((f) => h('li', { class: cls }, names?.get(f) ? h('b', { class: 'uid', dir: 'auto' }, names.get(f)!) : '', h('div', { class: 'hint mono', dir: 'ltr' }, formatFingerprint(f)))))
      : h('p', { class: 'hint' }, '(none)'),
  );
}

export function renderPlan(plan: RecipientChangePlan): HTMLElement {
  const label = (p: PlannedRecipient) => (p.escrow ? 'Recovery key' : nameOf(p.userIds[0]) || `Key …${tail(p.fingerprint)}`);
  const added = plan.after.filter((p) => plan.added.includes(p.fingerprint));
  const removed = plan.before.filter((p) => plan.removed.includes(p.fingerprint));
  const kept = plan.after.filter((p) => !plan.added.includes(p.fingerprint));
  const change = (cls: 'added' | 'removed', verb: string, p: PlannedRecipient) =>
    h('li', { class: cls }, h('span', { class: `badge ${cls}` }, verb), ' ', h('b', { class: 'uid', dir: 'auto' }, label(p)), h('div', { class: 'hint mono', dir: 'ltr' }, formatFingerprint(p.fingerprint)));
  return h(
    'div',
    { class: 'plan' },
    h('p', {}, `Who can open the secrets in ${plan.folder}/ after this:`),
    h('ul', { class: 'people-list' }, ...added.map((p) => change('added', 'gets access', p)), ...removed.map((p) => change('removed', 'loses access', p))),
    kept.length ? h('p', { class: 'hint' }, `Unchanged: ${kept.map(label).join(', ')}.`) : null,
    plan.admins
      ? h('div', { class: 'plan-admins' },
          h('p', {}, `Folder admins of ${plan.folder}/ (who can approve and remove people) also change:`),
          fprList('Admins before', plan.admins.before, '', adminNames(plan)),
          fprList('Admins after', plan.admins.after, '', adminNames(plan)))
      : null,
    plan.resign.length
      ? h('p', { class: 'hint' }, `Re-signed by you because their signer loses admin rights: ${plan.resign.map((r) => `${r.folder}/ (${[r.gpgId ? 'member list' : '', r.adminsFile ? 'admins' : ''].filter(Boolean).join(' + ')})`).join(', ')}`)
      : null,
    plan.droppedEscrow.length ? h('p', { class: 'hint' }, `Old recovery key(s) dropped: ${plan.droppedEscrow.map(formatFingerprint).join(', ')}`) : null,
    plan.childBoundaries.length ? h('p', { class: 'hint' }, `Sub-folders that keep their own members: ${plan.childBoundaries.map((c) => c + '/').join(', ')}`) : null,
    plan.warnings.includes('escrow-missing') ? h('p', { class: 'hint' }, 'This also restores the missing recovery key.') : null,
    h('details', { class: 'fpr-details' }, h('summary', {}, 'Show the full list (before → after)'),
      recipientList('Before', plan.before, (f) => (plan.removed.includes(f) ? 'removed' : null)),
      recipientList('After', plan.after, (f) => (plan.added.includes(f) ? 'added' : null))),
  );
}

function adminNames(plan: RecipientChangePlan): Map<string, string> {
  return new Map([...plan.before, ...plan.after].map((p) => [p.fingerprint, nameOf(p.userIds[0])]));
}
