/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {asn1, oids, util} from 'node-forge';
const {ByteBuffer} = util;

/**
 * Wraps Base58 decoding operations in
 * order to provide consistent error messages.
 *
 * @ignore
 * @example
 * > const pubkeyBytes = _base58Decode({
 *    decode: base58.decode,
 *    keyMaterial: this.publicKeyBase58,
 *    type: 'public'
 *   });
 * @param {object} options - The decoder options.
 * @param {Function} options.decode - The decode function to use.
 * @param {string} options.keyMaterial - The Base58 encoded
 * key material to decode.
 * @param {string} options.type - A description of the
 * key material that will be included
 * in an error message (e.g. 'public', 'private').
 *
 * @returns {object} - The decoded bytes. The data structure for the bytes is
 *   determined by the provided decode function.
 */
export function base58Decode({decode, keyMaterial, type}) {
  let bytes;
  try {
    bytes = decode(keyMaterial);
  } catch(e) {
    // do nothing
    // the bs58 implementation throws, forge returns undefined
    // this helper throws when no result is produced
  }
  if(bytes === undefined) {
    throw new TypeError(`The ${type} key material must be Base58 encoded.`);
  }
  return bytes;
}

export function privateKeyDerEncode({privateKeyBytes, seedBytes}) {
  if(!(privateKeyBytes || seedBytes)) {
    throw new TypeError('`privateKeyBytes` or `seedBytes` is required.');
  }
  if(!privateKeyBytes && !(Buffer.isBuffer(seedBytes) &&
    seedBytes.length === 32)) {
    throw new TypeError('`seedBytes` must be a 32 byte Buffer.');
  }
  if(!seedBytes && !(Buffer.isBuffer(privateKeyBytes) &&
    privateKeyBytes.length === 64)) {
    throw new TypeError('`privateKeyBytes` must be a 64 byte Buffer.');
  }
  let p;
  if(seedBytes) {
    p = seedBytes;
  } else {
    // extract the first 32 bytes of the 64 byte private key representation
    p = Buffer.from(privateKeyBytes.buffer, privateKeyBytes.byteOffset, 32);
  }
  // we can use the same DER for each key because keyLength is always 32 bytes
  const DERBuffer = Buffer.from([
    0x30,
    0x2e,
    0x02,
    0x01,
    0x00,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x70,
    0x04,
    0x22,
    0x04,
    0x20
  ]);
  return Buffer.concat([DERBuffer, p]);
}

export function publicKeyDerEncode({publicKeyBytes}) {
  if(!(Buffer.isBuffer(publicKeyBytes) && publicKeyBytes.length === 32)) {
    throw new TypeError('`publicKeyBytes` must be a 32 byte Buffer.');
  }
  // add a zero byte to the front of the publicKeyBytes, this results in
  // the bitstring being 256 bits vs. 170 bits (without padding)
  const zeroBuffer = Buffer.from(new Uint8Array([0]));
  const keyBuffer = new ByteBuffer(Buffer.concat([zeroBuffer, publicKeyBytes]));

  const a = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.SEQUENCE,
    true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(oids.EdDSA25519).getBytes()
        ),
      ]),
      // public key
      asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,
        keyBuffer.getBytes()),
    ]
  );

  const publicKeyDer = asn1.toDer(a);
  return Buffer.from(publicKeyDer.getBytes(), 'binary');
}
