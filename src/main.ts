import './ui/styles.css';
import { lockTrustHook, passThroughTrustHook, setTrustHook } from './core';
import { mountApp } from './ui/app';

// TODO(trust): install the .gpg-id signature-verifying hook here once
// implemented (docs/specs/gpg-id-signatures.md).
setTrustHook(passThroughTrustHook);
lockTrustHook();

mountApp(document.getElementById('app') as HTMLElement);

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  void navigator.serviceWorker.register('./sw.js', { scope: './' });
}
