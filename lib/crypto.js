/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {
  sign,
  verify,
  createPrivateKey,
  createPublicKey
} from 'crypto';

// used to export node's public keys to buffers
const publicKeyEncoding = {format: 'der', type: 'spki'};
// used to export node's private keys to buffers
const privateKeyEncoding = {format: 'der', type: 'pkcs8'};
// used to turn private key bytes into a buffer in DER format
const DER_PRIVATE_KEY_PREFIX = Buffer.from(
  '302e020100300506032b657004220420', 'hex');
// used to turn public key bytes into a buffer in DER format
const DER_PUBLIC_KEY_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * The key material is the part of the buffer after the DER Prefix.
 *
 * @param {Buffer} buffer - A DER encoded key buffer.
 *
 * @throws {Error} If the buffer does not contain a valid DER Prefix.
 *
 * @returns {Buffer} The key material part of the Buffer.
*/
function getKeyMaterial(buffer) {
  if(buffer.indexOf(DER_PUBLIC_KEY_PREFIX, 0) === 0) {
    return buffer.slice(DER_PUBLIC_KEY_PREFIX.length, buffer.length);
  }
  if(buffer.indexOf(DER_PRIVATE_KEY_PREFIX, 0) === 0) {
    return buffer.slice(DER_PRIVATE_KEY_PREFIX.length, buffer.length);
  }
  throw new Error('Expected Buffer to match Ed25519 Public or Private Prefix');
}

/**
 * Takes a Buffer or Uint8Array and adds a DER Private Prefix to it.
 * Allows Uint8Arrays to be interoperable with node's crypto functions.
 *
 * @param {object} options - Options to use.
 * @param {Buffer} [options.privateKeyBytes] - Required if no seedBytes.
 * @param {Buffer} [options.seedBytes] - Required if no privateKeyBytes.
 *
 * @throws {TypeError} Throws if the supplied buffer is not of the right size
 *  or not a Uint8Array or Buffer.
 *
 * @returns {Buffer} DER private key prefix + key bytes.
*/
function privateKeyDerEncode({privateKeyBytes, seedBytes}) {
  if(!(privateKeyBytes || seedBytes)) {
    throw new TypeError('`privateKeyBytes` or `seedBytes` is required.');
  }
  if(!privateKeyBytes && !(seedBytes instanceof Uint8Array &&
    seedBytes.length === 32)) {
    throw new TypeError('`seedBytes` must be a 32 byte Buffer.');
  }
  if(!seedBytes && !(privateKeyBytes instanceof Uint8Array &&
    privateKeyBytes.length === 64)) {
    throw new TypeError('`privateKeyBytes` must be a 64 byte Buffer.');
  }
  let p;
  if(seedBytes) {
    p = seedBytes;
  } else {
    // extract the first 32 bytes of the 64 byte private key representation
    p = privateKeyBytes.slice(0, 32);
  }
  return Buffer.concat([DER_PRIVATE_KEY_PREFIX, Buffer.from(p)]);
}

/**
 * Takes a Buffer of public key bytes and adds the DER Public Key Prefix to it.
 * Allows Uint8Arrays to be interoperable with node's crypto functions.
 *
 * @param {object} options - Options to use.
 * @param {Uint8Array} options.publicKeyBytes - The keyBytes.
 *
 * @throws {TypeError} Throws if the bytes are not Uint8Array or of length 32.
 *
 * @returns {Buffer} DER Public key Prefix + key bytes.
*/
function publicKeyDerEncode({publicKeyBytes}) {
  if(!(publicKeyBytes instanceof Uint8Array && publicKeyBytes.length === 32)) {
    throw new TypeError('`publicKeyBytes` must be a 32 byte Buffer.');
  }
  return Buffer.concat([DER_PUBLIC_KEY_PREFIX, Buffer.from(publicKeyBytes)]);
}

// seedBytes can be a TypedArray or a function that returns a TypedArray
const getSeedBytes = async seed => {
  if(typeof seed === 'function') {
    return seed();
  }
  return seed;
};

const api = {
  async generateKeyPairFromSeed(seed) {
    const seedBytes = await getSeedBytes(seed);
    const publicBytes = new Uint8Array(32);
    const privateBytes = new Uint8Array(64);
    privateBytes.set(seedBytes);
    privateBytes.set(publicBytes, 32);
    const privateKeyMaterial = privateKeyDerEncode(
      {privateKeyBytes: privateBytes});
    // node is more than happy to create a new private key using a DER
    const privateKey = await createPrivateKey({
      key: privateKeyMaterial,
      format: 'der',
      type: 'pkcs8'
    });
    // this expects either a PEM encoded key or a node privateKeyObject
    const publicKey = await createPublicKey(privateKey);
    const publicKeyBuffer = publicKey.export(publicKeyEncoding);
    const privateKeyBuffer = privateKey.export(privateKeyEncoding);
    const publicKeyBytes = getKeyMaterial(publicKeyBuffer);
    const privateKeyBytes = getKeyMaterial(privateKeyBuffer);
    return {
      publicKey: publicKeyBytes,
      secretKey: Buffer.concat([privateKeyBytes, publicKeyBytes])
    };
  },
  async generateKeyPair({randomBytes}) {
    return api.generateKeyPairFromSeed(randomBytes);
  },
  async sign(privateKeyBuffer, data) {
    const privateKey = await createPrivateKey({
      key: privateKeyDerEncode({privateKeyBytes: privateKeyBuffer}),
      format: 'der',
      type: 'pkcs8'
    });
    return sign(null, data, privateKey);
  },
  async verify(publicKeyBuffer, data, signature) {
    const publicKey = await createPublicKey({
      key: publicKeyDerEncode({publicKeyBytes: publicKeyBuffer}),
      format: 'der',
      type: 'spki'
    });
    return verify(null, data, publicKey, signature);
  }
};

export default api;
