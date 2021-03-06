/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import * as base58btc from 'base58-universal';
import {mockKey, seed} from './mock-data.js';
import multibase from 'multibase';
import multicodec from 'multicodec';
const should = chai.should();
const {expect} = chai;

import {Ed25519VerificationKey2020} from '../';

describe('Ed25519VerificationKey2020', () => {
  describe('constructor', () => {
    it('should auto-set key.id based on controller', async () => {
      const {publicKeyMultibase} = mockKey;
      const controller = 'did:example:1234';

      const keyPair = new Ed25519VerificationKey2020(
        {controller, publicKeyMultibase});
      expect(keyPair.id).to.equal(
        'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3');
    });

    it('should error if publicKeyMultibase property is missing', async () => {
      let error;
      try {
        new Ed25519VerificationKey2020({});
      } catch(e) {
        error = e;
      }
      expect(error).to.be.an.instanceof(TypeError);
      expect(error.message)
        .to.equal('The "publicKeyMultibase" property is required.');
    });
  });

  describe('generate', () => {
    it('should generate a key pair', async () => {
      let ldKeyPair;
      let error;
      try {
        ldKeyPair = await Ed25519VerificationKey2020.generate();
      } catch(e) {
        error = e;
      }

      should.not.exist(error);
      should.exist(ldKeyPair.privateKeyMultibase);
      should.exist(ldKeyPair.publicKeyMultibase);
      const privateKeyBytes = base58btc
        .decode(ldKeyPair.privateKeyMultibase.slice(1));
      const publicKeyBytes = base58btc
        .decode(ldKeyPair.publicKeyMultibase.slice(1));
      privateKeyBytes.length.should.equal(64);
      publicKeyBytes.length.should.equal(32);
    });

    it('should generate the same key from the same seed', async () => {
      const seed = new Uint8Array(32);
      seed.fill(0x01);
      const keyPair1 = await Ed25519VerificationKey2020.generate({seed});
      const keyPair2 = await Ed25519VerificationKey2020.generate({seed});
      expect(keyPair1.publicKeyMultibase).to.equal(keyPair2.publicKeyMultibase);
      expect(keyPair1.privateKeyMultibase).to
        .equal(keyPair2.privateKeyMultibase);
    });
  });

  describe('export', () => {
    it('should export id, type and key material', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate({
        seed: Buffer.from(seed, 'hex'), controller: 'did:example:1234'
      });
      const exported = await keyPair.export({
        publicKey: true, privateKey: true
      });

      expect(exported.controller).to.equal('did:example:1234');
      expect(exported.type).to.equal('Ed25519VerificationKey2020');
      expect(exported.id).to.equal('did:example:1234#' +
        'z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG');
      expect(exported).to.have.property('publicKeyMultibase',
        'z5tbhTS4zhFJHY1n4wPkiYBKkx5bNR2h4VnwkTgWWkjzt');
      expect(exported).to.have.property('privateKeyMultibase',
        'z3oVh1q7ATzrYZ14sMS13rKynAqyyzeHSbv2UpaqY1LggKEc4Ji2a69jtJnM' +
        'pGAzsFzY2NTUQymGK35XzgpywqcFv');
    });
  });

  describe('static fromFingerprint', () => {
    it('should round-trip load keys', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const fingerprint = keyPair.fingerprint();

      const newKey = Ed25519VerificationKey2020.fromFingerprint({fingerprint});
      expect(newKey.publicKeyMultibase).to.equal(keyPair.publicKeyMultibase);
    });
  });

  describe('static from', () => {
    it('should round-trip load exported keys', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate({
        seed: Buffer.from(seed, 'hex'), controller: 'did:example:1234'
      });
      const exported = await keyPair.export({
        publicKey: true, privateKey: true
      });
      const imported = await Ed25519VerificationKey2020.from(exported);

      expect(await imported.export({publicKey: true, privateKey: true}))
        .to.eql(exported);
    });
  });

  describe('fingerprint', () => {
    it('should create an Ed25519 key fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const fingerprint = keyPair.fingerprint();
      fingerprint.should.be.a('string');
      fingerprint.startsWith('z').should.be.true;
    });

    it('should be properly multicodec encoded', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const fingerprint = keyPair.fingerprint();
      const mcPubkeyBytes = multibase.decode(fingerprint);
      const mcType = multicodec.getCodec(mcPubkeyBytes);
      mcType.should.equal('ed25519-pub');
      const pubkeyBytes = multicodec.rmPrefix(mcPubkeyBytes);
      const encodedPubkey = 'z' + base58btc.encode(pubkeyBytes);
      encodedPubkey.should.equal(keyPair.publicKeyMultibase);
      expect(typeof keyPair.fingerprint()).to.equal('string');
    });
  });

  describe('verify fingerprint', () => {
    it('should verify a valid fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const fingerprint = keyPair.fingerprint();
      const result = keyPair.verifyFingerprint({fingerprint});
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.true;
    });

    it('should reject an improperly encoded fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const fingerprint = keyPair.fingerprint();
      const result = keyPair.verifyFingerprint(
        {fingerprint: fingerprint.slice(1)});
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal(
        '`fingerprint` must be a multibase encoded string.');
    });

    it('should reject an invalid fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const fingerprint = keyPair.fingerprint();
      // reverse the valid fingerprint
      const t = fingerprint.slice(1).split('').reverse().join('');
      const badFingerprint = fingerprint[0] + t;
      const result = keyPair.verifyFingerprint({fingerprint: badFingerprint});
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal(
        'The fingerprint does not match the public key.');
    });

    it('should reject a numeric fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const result = keyPair.verifyFingerprint({fingerprint: 123});
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal(
        '`fingerprint` must be a multibase encoded string.');
    });

    it('should reject an improperly encoded fingerprint', async () => {
      const keyPair = await Ed25519VerificationKey2020.generate();
      const result = keyPair.verifyFingerprint({fingerprint: 'zPUBLICKEYINFO'});
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal('Invalid encoding of fingerprint.');
    });

    it('generates the same fingerprint from the same seed', async () => {
      const seed = new Uint8Array(32);
      seed.fill(0x01);
      const keyPair1 = await Ed25519VerificationKey2020.generate({seed});
      const keyPair2 = await Ed25519VerificationKey2020.generate({seed});
      const fingerprint = keyPair1.fingerprint();
      const fingerprint2 = keyPair2.fingerprint();
      const result = keyPair2.verifyFingerprint({fingerprint});
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.true;
      fingerprint.should.equal(fingerprint2);
    });
  });
});
