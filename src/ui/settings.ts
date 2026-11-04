import { getTrustHook } from '../core';
import { fingerprint } from './components';
import { type AppCtx, storeLabel } from './context';
import { h } from './dom';
import { deviceKeyInfo, forgetDeviceKey } from './keystore';
import { connectScreen } from './setup';
import { splitUserId } from './people';
import { howSharingWorks } from './secrets';
import { createTrustPanel } from './trust';

/** Settings: connection, your key, trusted admins, folder status, about. */
export function settingsView(ctx: AppCtx): HTMLElement {
  const trust = createTrustPanel({ setStatus: ctx.toast });
  trust.card.classList.replace('card', 'panel');
  trust.settings.classList.replace('card', 'panel');
  const keyPanel = h('section', { class: 'panel' }, h('h3', {}, 'Your key'));
  void deviceKeyInfo().then((info) => {
    if (!info) return;
    const { name, email } = splitUserId(info.userIds[0] ?? '');
    keyPanel.append(
      h('p', {}, h('b', { class: 'uid', dir: 'auto' }, name || 'Your key'), email ? h('span', { class: 'hint uid', dir: 'auto' }, ` ${email}`) : ''),
      h('p', { class: 'hint' }, 'Key fingerprint (your unique key code — people compare this to know it is really you):'),
      h('p', {}, fingerprint(info.fingerprint)),
      h('p', { class: 'hint' }, 'Stored in this browser, protected by your passphrase.'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: () => ctx.session.lock() }, 'Lock now'),
        h('button', {
          type: 'button',
          class: 'danger',
          onclick: () => {
            if (!confirm('Remove your key from this browser? You need the key file (or a new approval) to use g00pass here again.')) return;
            ctx.session.lock();
            forgetDeviceKey();
            ctx.rerender();
          },
        }, 'Remove key from this browser')),
    );
  });
  const snapshot = ctx.snapshot();
  if (snapshot) void trust.refresh(snapshot, ctx.config()).then(() => {
    const t = trust.card.querySelector('h2');
    if (t) t.replaceWith(h('h3', {}, 'Folder status'));
    const s = trust.settings.querySelector('h2');
    if (s) s.replaceWith(h('h3', {}, 'Trusted admins'));
  });
  return h(
    'div',
    { class: 'settings' },
    h('section', { class: 'panel' }, h('h3', {}, 'Connection'), h('p', { class: 'hint' }, `Connected to ${storeLabel(ctx.config())} (branch ${ctx.config().branch}).`), connectScreen(ctx, { embedded: true }),
      h('button', { type: 'button', class: 'ghost small', onclick: () => { ctx.tokens.clear(); ctx.rerender(); } }, 'Forget token')),
    keyPanel,
    trust.settings,
    trust.card,
    h('section', { class: 'panel' }, h('h3', {}, 'What the words mean'), glossary(), howSharingWorks()),
    h('section', { class: 'panel' }, h('h3', {}, 'About'), h('p', { class: 'hint' }, `g00pass v${__APP_VERSION__} (${__APP_COMMIT__}). Trust policy: ${getTrustHook().name}. Nothing leaves this browser except calls to api.github.com.`)),
  );
}

function glossary(): HTMLElement {
  const row = (term: string, text: string) => h('div', { class: 'gloss' }, h('dt', {}, term), h('dd', {}, text));
  return h(
    'dl',
    { class: 'glossary' },
    row('Key', 'Your personal digital ID. It stays in this browser, protected by your passphrase, and opens the secrets you are allowed to read.'),
    row('Fingerprint', 'The long code of letters and numbers that identifies a key. Names can be faked; fingerprints cannot. When it matters, compare it with the person directly.'),
    row('Member', 'Someone whose key can open a folder’s secrets.'),
    row('Admin', 'Someone who can add or remove members. Trusted admins are the ones this browser accepts member lists from; you confirmed them when you first connected.'),
    row('Recovery key', 'A backup key kept somewhere safe by your team, so secrets can be recovered if everyone loses their key. It can open everything and cannot be removed.'),
    row('Token', 'A GitHub access code that lets this app read (or write) the repository. It only moves the locked files; your key is what opens them.'),
    row('Requests repo', 'A private GitHub repository where access requests arrive as issues.'),
    row('Rotation', 'Changing a password where it is actually used (the account or service) after someone leaves.'),
  );
}
