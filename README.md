# Ed25519VerificationKey2020 Key Pair Library for Linked Data _(@digitalbazaar/ed25519-verification-key-2020)_

[![Node.js CI](https://github.com/digitalbazaar/ed25519-verification-key-2020/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/ed25519-verification-key-2020/actions?query=workflow%3A%22Node.js+CI%22)

> Javascript library for generating and working with Ed25519VerificationKey2020 key pairs, for use with crypto-ld.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

For use with:

* [`crypto-ld`](https://github.com/digitalbazaar/crypto-ld) `^4.0.0`.
* [`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures) `digitalbazaar/jsonld-signatures#v6.x`
* `ed25519-signature-2020`
* [`vc-js`](https://github.com/digitalbazaar/vc-js) `digitalbazaar/vc-js#v7.x`

See also (related specs):

* [Ed25519VerificationKey2020](https://w3c-ccg.github.io/lds-ed25519-2020/#ed25519verificationkey2020) spec.

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 14+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/ed25519-verification-key-2020.git
cd ed25519-verification-key-2020
npm install
```

## Usage

### Generating a new public/private key pair

To generate a new public/private key pair:

* `{string} [controller]` Optional controller URI or DID to initialize the
  generated key. (This will also init the key id.) 
* `{string} [seed]` Optional deterministic seed value from which to generate the 
  key.

```js
import {Ed25519VerificationKey2020} from '@digitalbazaar/ed25519-verification-key-2020';

const edKeyPair = await Ed25519VerificationKey2020.generate();
```

### Importing a key pair from storage

To create an instance of a public/private key pair from data imported from
storage, use `.from()`:

```js
const serializedKeyPair = { ... };

const keyPair = await Ed25519VerificationKey2020.from(serializedKeyPair);
````

### Exporting the public key only

To export just the public key of a pair:

```js
await keyPair.export({publicKey: true});
// ->
{ 
  type: 'Ed25519VerificationKey2020',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf'
}
```

### Exporting the full public-private key pair

To export the full key pair, including private key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems):

```js
await keyPair.export({publicKey: true, privateKey: true});
// ->
{
  type: 'Ed25519VerificationKey2020',
  id: 'did:example:1234#z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zEYJrMxWigf9boyeJMTRN4Ern8DJMoCXaLK77pzQmxVjf',
  privateKeyMultibase: 'z4E7Q4neNHwv3pXUNzUjzc6TTYspqn9Aw6vakpRKpbVrCzwKWD4hQDHnxuhfrTaMjnR8BTp9NeUvJiwJoSUM6xHAZ'
}
```

### Generating and verifying key fingerprint

To generate a fingerprint:

```js
keyPair.fingerprint();
// ->
'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3'
```

To verify a fingerprint:

```js
const fingerprint = 'z6MkszZtxCmA2Ce4vUV132PCuLQmwnaDD5mw2L23fGNnsiX3';
keyPair.verifyFingerprint({fingerprint});
// ->
{valid: true}
```

### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = Ed25519VerificationKey2020.generate();

const {sign} = keyPair.signer();

const data = Buffer.from('test data to sign', 'utf8');
const signatureValue = await sign({data});
```

### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = Ed25519VerificationKey2020.generate();

const {verify} = keyPair.verifier();

const valid = await verify({data, signature});
// true
```


## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © 2020 Digital Bazaar
