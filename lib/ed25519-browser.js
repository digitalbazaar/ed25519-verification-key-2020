/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {checkKeyBytes} from './validators.js';
import * as ed25519 from '@noble/ed25519';

// browser MUST provide "crypto.getRandomValues"
const crypto = globalThis.crypto;
if(!crypto.getRandomValues) {
  throw new Error('Browser does not provide "crypto.getRandomValues".');
}

export default {
  async generateKeyPair() {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const keyPair = await generateKeyPairFromSeed(seed);
    seed.fill(0);
    return keyPair;
  },
  generateKeyPairFromSeed,
  async sign(secretKey, data) {
    return ed25519.sign(data, secretKey.slice(0, 32));
  },
  async verify(publicKey, data, signature) {
    return ed25519.verify(signature, data, publicKey);
  },
  async sha256digest({data}) {
    return crypto.subtle.digest('SHA-256', data);
  }
};

async function generateKeyPairFromSeed(seed) {
  checkKeyBytes({
    bytes: seed,
    expectedLength: 32,
  });
  const publicKey = await ed25519.getPublicKey(seed);
  const secretKey = new Uint8Array(64);
  secretKey.set(seed);
  secretKey.set(publicKey, seed.length);
  return {
    publicKey,
    secretKey
  };
}
