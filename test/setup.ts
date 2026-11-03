import { passThroughTrustHook, setTrustHook } from '../src/core';

// Production default is `unconfiguredTrustHook` (refuses everything) until
// src/main.ts installs `signatureTrustHook`. Core unit tests that are not about
// trust policy run with the pass-through; trust tests install their own hook.
setTrustHook(passThroughTrustHook);
