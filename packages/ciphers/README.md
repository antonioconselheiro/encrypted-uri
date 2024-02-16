> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI - ciphers

[![npm version](https://badge.fury.io/js/@encrypted-uri%2Fciphers.svg)](https://github.com/antonioconselheiro/encrypted-uri)
[![Npm Total Downloads](https://img.shields.io/npm/dt/@encrypted-uri/ciphers.svg)](https://github.com/antonioconselheiro/encrypted-uri)
[![Npm Monthly Downloads](https://img.shields.io/npm/dm/@encrypted-uri/ciphers.svg)](https://github.com/antonioconselheiro/encrypted-uri)

Include AES algorithms from @noble/ciphers into Encrypted URI (@encrypted-uri/core).

Support for Encrypted URI using _@scure_ and _@noble_ packages.

## Installation

```npm install @encrypted-uri/core @encrypted-uri/ciphers --save```

```typescript
import { EncryptedURI } from '@encrypted-uri/core';
import '@encrypted-uri/ciphers/aes';
import '@encrypted-uri/ciphers/hashes';

EncryptedURI.encrypt({
   algorithm: 'aes/cbc',
   params: { iv: 'a24567b823f5c7918736194ab5c2e83d' },
   content: 'secret message',
   key: 'secret key'
});
// encrypted:aes/cbc?iv=a24567b823f5c7918736194ab5c2e83d;...<cypher>

EncryptedURI.encrypt({
   algorithm: 'aes/cbc',
   queryString: 'a24567b823f5c7918736194ab5c2e83d',
   content: 'secret message',
   key: 'secret key'
});
// encrypted:aes/cbc?a24567b823f5c7918736194ab5c2e83d;...<cypher>


EncryptedURI.encrypt({
   content: 'secret message',
   key: 'secret key'
});
// default algorithm is aes/cbc from webcrypto
// encrypted:?a24567b823f5c7918736194ab5c2e83d;rtyu...<cypher>

```