import './ui/styles.css';
import { lockTrustHook, setTrustHook, signatureTrustHook } from './core';
import { mountApp } from './ui/app';

// Trust policy: .gpg-id signatures + pinned anchors + folder admins
// (docs/specs/gpg-id-signatures.md). Locking also freezes the trust
// environment (storage, store identity, history, clock).
setTrustHook(signatureTrustHook);
lockTrustHook();

mountApp(document.getElementById('app') as HTMLElement);

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  void navigator.serviceWorker.register('./sw.js', { scope: './' });
}
