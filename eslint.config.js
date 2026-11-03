import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

/**
 * Trust choke-point enforcement: OpenPGP encryption may only be performed in
 * src/core/crypto/encrypt.ts, which only accepts a VerifiedRecipientSet minted
 * by src/core/trust.ts. Everything else is forbidden from calling
 * openpgp.encrypt / importing `encrypt` from openpgp.
 */
const ENCRYPT_ALLOWED = ['src/core/crypto/encrypt.ts'];

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'src/sw-template.js'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['src/**/*.ts'],
    ignores: ENCRYPT_ALLOWED,
    rules: {
      'no-console': 'error',
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'openpgp',
              importNames: ['encrypt', 'encryptSessionKey'],
              message: 'Encrypt only via src/core/crypto/encrypt.ts (trust choke-point).',
            },
          ],
        },
      ],
      'no-restricted-properties': [
        'error',
        { object: 'openpgp', property: 'encrypt', message: 'Use encryptToVerified() (trust choke-point).' },
        { object: 'openpgp', property: 'encryptSessionKey', message: 'Use encryptToVerified().' },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.object.name='localStorage'][callee.property.name='setItem'] > Literal[value=/token/i]",
          message: 'Tokens must never be stored in localStorage (memory or sessionStorage only).',
        },
        {
          // Message#encrypt / Message.encryptSessionKey / packet .encrypt(): any `.encrypt(` call
          selector: "CallExpression[callee.type='MemberExpression'][callee.property.name=/^encrypt(SessionKey)?$/]",
          message: 'Encrypt only via encryptToVerified() (trust choke-point); no Message#encrypt / .encrypt() calls.',
        },
        {
          selector: "MemberExpression[computed=true][property.value=/^encrypt/]",
          message: 'Encrypt only via encryptToVerified() (trust choke-point).',
        },
      ],
    },
  },
  {
    files: ['src/core/crypto/encrypt.ts'],
    rules: { 'no-console': 'error' },
  },
);
