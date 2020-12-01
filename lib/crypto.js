import {
  sign,
  verify,
  createPrivateKey,
  createPublicKey
} from 'crypto';
import {asn1, ed25519, util} from 'node-forge';
import {privateKeyDerEncode} from './util.js';

const {privateKeyFromAsn1, publicKeyFromAsn1} = ed25519;
const {ByteBuffer} = util;
const publicKeyEncoding = {format: 'der', type: 'spki'};
const privateKeyEncoding = {format: 'der', type: 'pkcs8'};

const api = {
  async generateKeyPairFromSeed(seed) {
    // create a node private key
    // const privateKey = _privateKeyNode12.create({seedBytes});
    // create a node public key from the private key
    // const publicKey = createPublicKey(privateKey);
    const privateKeyMaterial = privateKeyDerEncode({seedBytes: seed});
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
      secretKey: privateKeyBytes
    };
  },
  async generateKeyPair({randomBytes}) {
    return api.generateKeyPairFromSeed(randomBytes);
  },
  async sign(privateKeyBuffer, data) {
    return sign(null, data, privateKeyBuffer);
  },
  async verify(publicKeyBuffer, data, signature) {
    return verify(null, data, publicKeyBuffer, signature);
  }
};

export default api;
