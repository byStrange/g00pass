import { getTrustHook } from '../core';
import { fingerprint } from './components';
import { type AppCtx, storeLabel } from './context';
import { h } from './dom';
import { deviceKeyInfo, forgetDeviceKey } from './keystore';
import { connectScreen } from './setup';
import { createTrustPanel } from './trust';

/** Settings: connection, your key, trusted admins, folder status, about. */
export function settingsView(ctx: AppCtx): HTMLElement {
  const trust = createTrustPanel({ setStatus: ctx.toast });
  trust.card.classList.replace('card', 'panel');
  trust.settings.classList.replace('card', 'panel');
  const keyPanel = h('section', { class: 'panel' }, h('h3', {}, 'Your key'));
  void deviceKeyInfo().then((info) => {
    if (!info) return;
    keyPanel.append(
      h('p', {}, fingerprint(info.fingerprint)),
      h('p', { class: 'hint' }, info.userIds.join(', ')),
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
    h('section', { class: 'panel' }, h('h3', {}, 'About'), h('p', { class: 'hint' }, `g00pass v${__APP_VERSION__} (${__APP_COMMIT__}). Trust policy: ${getTrustHook().name}. Nothing leaves this browser except calls to api.github.com.`)),
  );
}
