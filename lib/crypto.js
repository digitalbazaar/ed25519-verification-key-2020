import {
  sign,
  verify,
  createPrivateKey,
  createPublicKey
} from 'crypto';
import {asn1, ed25519, util} from 'node-forge';
import {privateKeyDerEncode, publicKeyDerEncode} from './util.js';

const {privateKeyFromAsn1, publicKeyFromAsn1} = ed25519;
const {ByteBuffer} = util;
const publicKeyEncoding = {format: 'der', type: 'spki'};
const privateKeyEncoding = {format: 'der', type: 'pkcs8'};

// FIXME someone more familar with TypedArrays and Buffers
// should review this
const typedArrayToBuffer = array => {
  const length = array.byteLength + array.byteOffset;
  const arrayBuffer = array.buffer.slice(array.byteOffset, length);
  return Buffer.from(arrayBuffer, array.byteOffset, length);
};

// seedBytes can be a TypedArray or a function that returns a TypedArray
const getSeedBytes = async seed => {
  if(typeof seed === 'function') {
    return seed();
  }
  return seed;
};

// helper function that takes an TypedArray of private bytes and turns it
// into a Buffer containing a DER encoded key
const privateBytesToDer = array => privateKeyDerEncode(
  {privateKeyBytes: typedArrayToBuffer(array)});

// helper function that takes a TypedArray of public bytes and turns it
// into a Buffer containing a DER encoded key
const publicBytesToDer = array => publicKeyDerEncode(
  {publicKeyBytes: typedArrayToBuffer(array)});

const api = {
  async generateKeyPairFromSeed(seed) {
    const seedBytes = await getSeedBytes(seed);
    const publicBytes = new Uint8Array(32);
    const privateBytes = new Uint8Array(64);
    privateBytes.set(seedBytes);
    privateBytes.set(publicBytes, 32);
    const privateKeyMaterial = privateBytesToDer(privateBytes);
    const privateKey = await createPrivateKey({
      key: privateKeyMaterial,
      format: 'der',
      type: 'pkcs8'
    });
    const publicKey = await createPublicKey(privateKey);
    // export the keys and extract key bytes from the exported DERs
    const publicKeyBytes = publicKeyFromAsn1(
      asn1.fromDer(new ByteBuffer(publicKey.export(publicKeyEncoding))));
    const {privateKeyBytes} = privateKeyFromAsn1(
      asn1.fromDer(new ByteBuffer(privateKey.export(privateKeyEncoding))));
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
      key: privateBytesToDer(privateKeyBuffer),
      format: 'der',
      type: 'pkcs8'
    });
    return sign(null, data, privateKey);
  },
  async verify(publicKeyBuffer, data, signature) {
    const publicKey = await createPublicKey({
      key: publicBytesToDer(publicKeyBuffer),
      format: 'der',
      type: 'spki'
    });
    return verify(null, data, publicKey, signature);
  }
};

export default api;
