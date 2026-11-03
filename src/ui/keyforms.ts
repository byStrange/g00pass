import { G00passError, checkPassphrase, generateEnrollmentKey, inspectImportedKey } from '../core';
import { form, field, help, input, notice } from './components';
import { h } from './dom';
import { saveDeviceKey } from './keystore';

/**
 * Create / import the device key. The key is stored only passphrase-protected
 * (iterated S2K); the passphrase never leaves the page.
 */

export function createKeyForm(onDone: (fingerprint: string) => void, onError: (m: string) => void, defaults: { name?: string; email?: string } = {}): HTMLElement {
  const name = input({ required: true, autocomplete: 'name', value: defaults.name ?? '' });
  const email = input({ type: 'email', required: true, autocomplete: 'email', value: defaults.email ?? '' });
  const p1 = input({ type: 'password', autocomplete: 'new-password', required: true });
  const p2 = input({ type: 'password', autocomplete: 'new-password', required: true });
  return form(
    async () => {
      if (p1.value !== p2.value) throw new G00passError('Passphrases do not match.');
      const weak = checkPassphrase(p1.value);
      if (weak) throw new G00passError(weak);
      try {
        const k = await generateEnrollmentKey({ name: name.value, email: email.value, passphrase: p1.value });
        await saveDeviceKey(k.privateKeyArmored);
        onDone(k.fingerprint);
      } finally {
        p1.value = '';
        p2.value = '';
      }
    },
    onError,
    'Create my key',
    'Creating key…',
    field('Your name', name),
    field('E-mail', email),
    field('Passphrase', p1, 'At least 12 characters. It protects your key on this device and never leaves it. If you forget it, the key cannot be recovered.'),
    field('Repeat passphrase', p2),
  );
}

export function importKeyForm(onDone: (fingerprint: string) => void, onError: (m: string) => void): HTMLElement {
  const ta = h('textarea', { rows: '6', spellcheck: 'false', placeholder: '-----BEGIN PGP PRIVATE KEY BLOCK-----' });
  const file = h('input', { type: 'file', accept: '.asc,.key,.gpg,.txt,text/plain' });
  file.addEventListener('change', async () => {
    const f = file.files?.[0];
    if (f && f.size < 256 * 1024) ta.value = await f.text();
    file.value = '';
  });
  return form(
    async () => {
      const armored = ta.value;
      try {
        // Same checks as enrollment (protected, v4, accepted algorithm) before storing.
        await inspectImportedKey(armored);
        const info = await saveDeviceKey(armored);
        onDone(info.fingerprint);
      } finally {
        ta.value = '';
      }
    },
    onError,
    'Use this key',
    'Checking key…',
    field('Paste your private key', ta),
    h('label', { class: 'file' }, 'or choose a file: ', file),
    help(
      'Which key?',
      h('p', {}, 'Your personal OpenPGP private key, passphrase-protected (v4, Ed25519 or RSA ≥ 3072). Export it with:'),
      h('pre', { class: 'code' }, 'gpg --export-secret-keys --armor YOUR-FINGERPRINT'),
      notice('info', 'It is stored encrypted in this browser only. Keys protected with Argon2 cannot be unlocked here.'),
    ),
  );
}

/** "Create" / "Import" chooser. */
export function keyChooser(onDone: (fingerprint: string) => void, onError: (m: string) => void, opts: { preferCreate?: boolean; defaults?: { name?: string; email?: string } } = {}): HTMLElement {
  const body = h('div', { class: 'chooser-body' });
  const createBtn = h('button', { type: 'button', class: 'choice', 'aria-pressed': 'false' }, h('b', {}, 'Create a new key'), h('span', { class: 'hint' }, "I'm new and need access"));
  const importBtn = h('button', { type: 'button', class: 'choice', 'aria-pressed': 'false' }, h('b', {}, 'I already have a key'), h('span', { class: 'hint' }, 'An admin already added my key'));
  const pick = (create: boolean) => {
    createBtn.setAttribute('aria-pressed', String(create));
    importBtn.setAttribute('aria-pressed', String(!create));
    body.replaceChildren(create ? createKeyForm(onDone, onError, opts.defaults) : importKeyForm(onDone, onError));
  };
  createBtn.addEventListener('click', () => pick(true));
  importBtn.addEventListener('click', () => pick(false));
  pick(opts.preferCreate ?? false);
  return h('div', { class: 'chooser' }, h('div', { class: 'choices' }, importBtn, createBtn), body);
}
