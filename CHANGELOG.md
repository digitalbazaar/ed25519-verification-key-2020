# @digitalbazaar/ed25519-verification-key-2020 ChangeLog

## 3.1.0 - 2021-06-24

### Changed
- Allow keys to be created purely for verification or purely for signing.

## 3.0.0 - 2021-06-19

### Fixed
- **BREAKING**: Fix improperly encoded public and private keys.
- Perform better key validation when creating a key.
- Remove TextEncoder/TextDecoder polyfill (provided in all environments now).
- Do not leak private key details in errors.
- Fix error string consistency.

## 2.1.1 - 2021-04-08

### Fixed
- Ensure `signer()` and `verifier()` objects have an `id` property (for jsigs).

## 2.1.0 - 2021-04-01

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
