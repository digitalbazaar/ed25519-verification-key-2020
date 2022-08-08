# @digitalbazaar/ed25519-verification-key-2020 ChangeLog

## 4.1.0 - 

### Added
- Added a new validators file with `assertKeyBytes.`
- Public key byte checks have error codes compatible with the `did:key` spec.

## Changed
- Previous key bytes checks are now all done with `checkKeyBytes`.

## Fixed
- No longer throw a `TypeError` when passing in a Uint8Array of the wrong length.

## 4.0.0 - 2022-06-02

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- **BREAKING**: Use `globalThis` to get `crypto` in browsers.
- Update dependencies.
- Lint module.

## 3.3.0 - 2022-05-05

### Changed
- Replace underlying ed25519 implementation with `@noble/ed25519`. This
  should be a non-breaking change.

## 3.2.0 - 2021-10-15

### Added
- Add support for `JsonWebKey2020` and JWK import/export, as well as
  JWK thumbprint function.

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
