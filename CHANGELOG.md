# @digitalbazaar/ed25519-verification-key-2020 ChangeLog

## 1.1.0 -

## Changed
- Update to use `crypto-ld v5.0`. No public API changes from the previous v4 dep.

## Added
- Add `Ed25519VerificationKey2020.fromEd25519VerificationKey2018()` method,
  for backwards compatibility with the `Ed25519VerificationKey2018` key type.
  See "Converting from previous Ed25519VerificationKey2018 key type" section
  of the README for details.

## 1.0.0 - 2021-02-27

Initial version.
