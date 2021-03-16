/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58btc from 'base58-universal';
import ed25519 from './ed25519.js';
import {LDKeyPair} from 'crypto-ld';

const SUITE_ID = 'Ed25519VerificationKey2020';

export class Ed25519VerificationKey2020 extends LDKeyPair {
  /**
   * An implementation of the Ed25519VerificationKey2020 spec, for use with
   * Linked Data Proofs.
   *
   * @see https://w3c-ccg.github.io/lds-ed25519-2020/#ed25519verificationkey2020
   * @see https://github.com/digitalbazaar/jsonld-signatures
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.controller - Controller DID or document url.
   * @param {string} [options.id] - Key id, typically composed of controller
   *   URL and key fingerprint as hash fragment.
   * @param {string} options.publicKeyMultibase - Multibase encoded Public Key.
   * @param {string} [options.privateKeyMultibase] - Multibase Private Key.
   */
  constructor(options = {}) {
    super(options);
    this.type = SUITE_ID;
    this.publicKeyMultibase = options.publicKeyMultibase;
    if(!this.publicKeyMultibase) {
      throw new TypeError('The "publicKeyMultibase" property is required.');
    }
    this.privateKeyMultibase = options.privateKeyMultibase;
    if(this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`;
    }
  }

  /**
   * Creates an Ed25519 Key Pair from an existing serialized key pair.
   *
   * @param {object} options - Key pair options (see constructor).
   * @example
   * > const keyPair = await Ed25519VerificationKey2020.from({
   * controller: 'did:ex:1234',
   * type: 'Ed25519VerificationKey2020',
   * publicKeyMultibase,
   * privateKeyMultibase
   * });
   *
   * @returns {Promise<Ed25519VerificationKey2020>} An Ed25519 Key Pair.
   */
  static async from(options) {
    return new Ed25519VerificationKey2020(options);
  }

  /**
   * Generates a KeyPair with an optional deterministic seed.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {Uint8Array} [options.seed] - A 32-byte array seed for a
   *   deterministic key.
   *
   * @returns {Promise<Ed25519VerificationKey2020>} Resolves with generated
   *   public/private key pair.
   */
  static async generate({seed, ...keyPairOptions} = {}) {
    let keyObject;
    if(seed) {
      keyObject = await ed25519.generateKeyPairFromSeed(seed);
    } else {
      keyObject = await ed25519.generateKeyPair();
    }
    return new Ed25519VerificationKey2020({
      // prefix with `z` to indicate multi-base base58btc encoding
      publicKeyMultibase: `z${base58btc.encode(keyObject.publicKey)}`,
      privateKeyMultibase: `z${base58btc.encode(keyObject.secretKey)}`,
      ...keyPairOptions
    });
  }

  /**
   * Creates an instance of Ed25519VerificationKey2020 from a key fingerprint.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.fingerprint - Multibase encoded key fingerprint.
   *
   * @returns {Ed25519VerificationKey2020} Returns key pair instance (with
   *   public key only).
   */
  static fromFingerprint({fingerprint} = {}) {
    if(!fingerprint ||
      !(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      throw new Error('`fingerprint` must be a multibase encoded string.');
    }

    // skip leading `z` that indicates base58 encoding
    const buffer = base58btc.decode(fingerprint.substr(1));

    // buffer is: 0xed 0x01 <public key bytes>
    if(buffer[0] === 0xed && buffer[1] === 0x01) {
      return new Ed25519VerificationKey2020({
        publicKeyMultibase: `z${base58btc.encode(buffer.slice(2))}`
      });
    }

    throw new Error(`Unsupported fingerprint "${fingerprint}".`);
  }

  get _publicKeyBuffer() {
    return this.publicKeyMultibase &&
      base58btc.decode(this.publicKeyMultibase.substr(1));
  }

  get _privateKeyBuffer() {
    return this.privateKeyMultibase &&
      base58btc.decode(this.privateKeyMultibase.substr(1));
  }

  /**
   * Generates and returns a multiformats encoded
   * ed25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    // ed25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec ed25519-pub 0xed01 + key bytes)
    const pubkeyBytes = this._publicKeyBuffer;
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    buffer[0] = 0xed;
    buffer[1] = 0x01;
    buffer.set(pubkeyBytes, 2);
    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${base58btc.encode(buffer)}`;
  }

  /**
   * Exports the serialized representation of the KeyPair
   * and other information that json-ld Signatures can use to form a proof.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {boolean} [options.publicKey] - Export public key material?
   * @param {boolean} [options.privateKey] - Export private key material?
   *
   * @returns {object} A public key object
   *   information used in verification methods by signatures.
   */
  export({publicKey = false, privateKey = false}) {
    const exportedKey = super.export({publicKey, privateKey});
    if(publicKey) {
      exportedKey.publicKeyMultibase = this.publicKeyMultibase;
    }
    if(privateKey) {
      exportedKey.privateKeyMultibase = this.privateKeyMultibase;
    }
    return exportedKey;
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @example
   * > edKeyPair.verifyFingerprint({fingerprint: 'z2S2Q6MkaFJewa'});
   * {valid: true};
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.fingerprint - A public key fingerprint.
   *
   * @returns {{valid: boolean, error: *}} Result of verification.
   */
  verifyFingerprint({fingerprint} = {}) {
    // fingerprint should have `z` prefix indicating
    // that it's multi-base encoded
    if(!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        error: new Error('`fingerprint` must be a multibase encoded string.'),
        valid: false
      };
    }
    let fingerprintBuffer;
    try {
      fingerprintBuffer = base58btc.decode(fingerprint.substr(1));
      if(!fingerprintBuffer) {
        throw new TypeError('Invalid encoding of fingerprint.');
      }
    } catch(e) {
      return {error: e, valid: false};
    }

    const buffersEqual = _isEqualBuffer(this._publicKeyBuffer,
      fingerprintBuffer.slice(2));

    // validate the first two multicodec bytes 0xed01
    const valid = fingerprintBuffer[0] === 0xed &&
      fingerprintBuffer[1] === 0x01 &&
      buffersEqual;
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }
    return {valid};
  }

  signer() {
    const privateKeyBuffer = this._privateKeyBuffer;
    if(!privateKeyBuffer) {
      throw new Error('No private key to sign with.');
    }

    return {
      async sign({data}) {
        return ed25519.sign(privateKeyBuffer, data);
      },
    };
  }

  verifier() {
    const publicKeyBuffer = this._publicKeyBuffer;

    return {
      async verify({data, signature}) {
        return ed25519.verify(publicKeyBuffer, data, signature);
      },
    };
  }
}

Ed25519VerificationKey2020.suite = SUITE_ID;

function _isEqualBuffer(buf1, buf2) {
  if(buf1.length !== buf2.length) {
    return false;
  }
  for(let i = 0; i < buf1.length; i++) {
    if(buf1[i] !== buf2[i]) {
      return false;
    }
  }
  return true;
}
