/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();

import {Ed25519VerificationKey2020} from '../';
import {mockKey, mockNodeKey} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
import * as base58btc from 'base58-universal';

const keyPair = new Ed25519VerificationKey2020({
  controller: 'did:example:1234',
  ...mockKey
});

const signer = keyPair.signer();
const verifier = keyPair.verifier();

// the same signature should be generated on every test platform
// (eg. browser, node14)
const targetSignatureBase58 = '57PG4Ahy97k8iwmRVf8bEK9ZXuy8Q7wz3Mx' +
  'BQkwrNE5jsGaiWdzYnEK1SiP8yZ4VfEujd4FCkfxzUaBQQEZzL6PK';

describe('sign and verify', () => {
  it('works properly', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    base58btc.encode(signature).should.equal(targetSignatureBase58);
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });

  it('fails if signing data is changed', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });

  // this simulates what happens when a backend key creates a signature
  // and it is verified on both the backend and the front end
  it('verifies with key & signature produced using node crypto', async () => {
    const _keyPair = new Ed25519VerificationKey2020({
      controller: 'did:example:1234',
      ...mockNodeKey
    });
    const data = stringToUint8Array(mockNodeKey.data);
    // this signature was produced by node's crypto.sign function
    // and is base58 encoded
    const signature = base58btc.decode(mockNodeKey.signature);
    const result = await _keyPair.verifier().verify({data, signature});
    result.should.be.true;
  });
});
