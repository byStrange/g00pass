import './ui/styles.css';
import { passThroughTrustHook, setTrustHook } from './core';
import { mountApp } from './ui/app';

// TODO(trust): install the .gpg-id signature-verifying hook here once
// implemented (docs/specs/gpg-id-signatures.md).
setTrustHook(passThroughTrustHook);

mountApp(document.getElementById('app') as HTMLElement);

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  void navigator.serviceWorker.register('./sw.js', { scope: './' });
}
