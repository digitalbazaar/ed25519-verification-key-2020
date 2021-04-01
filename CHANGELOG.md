# @digitalbazaar/ed25519-verification-key-2020 ChangeLog

## 2.1.0 -

### Added
- Add `revoked` export tests, `SUITE_CONTEXT` class property. (To support
  `CryptoLD`'s new `fromKeyId()` method.)

## 2.0.0 - 2021-03-17

## Changed
- Update to use `crypto-ld v5.0`.
- **BREAKING**: Removed helper methods `addPublicKey` and `addPrivateKey`.

## Added
- Add `Ed25519VerificationKey2020.fromEd25519VerificationKey2018()` method,
  for backwards compatibility with the `Ed25519VerificationKey2018` key type.
  See "Converting from previous Ed25519VerificationKey2018 key type" section
  of the README for details.

## 1.0.0 - 2021-02-27

Initial version.
