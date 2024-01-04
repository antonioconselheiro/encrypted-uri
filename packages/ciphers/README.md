> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI - ciphers
Include AES algorithms from @noble/ciphers into Encrypted URI (@encrypted-uri/core). Only ```initialization vector``` and ```number once``` params are included.

Support for Encrypted URI using _@scure_ and _@noble_ packages.

*under beta test*

## Installation

```npm install @encrypted-uri/core @encrypted-uri/ciphers --save```

```typescript
import { EncryptedURI } from '@encrypted-uri/core';
import { supportAES } from '@encrypted-uri/ciphers';

supportAES();

EncryptedURI.encrypt({
   algorithm: 'aes/cbc',
   params: { iv: 'a24567b823f5c7918736194ab5c2e83d' },
   content: 'secret message',
   key: 'secret key'
});
// encrypted:aes/cbc?iv=a24567b823f5c7918736194ab5c2e83d;rtyu...<cypher>

EncryptedURI.encrypt({
   algorithm: 'aes/cbc',
   queryString: 'a24567b823f5c7918736194ab5c2e83d',
   content: 'secret message',
   key: 'secret key'
});
// encrypted:aes/cbc?a24567b823f5c7918736194ab5c2e83d;rtyu...<cypher>


EncryptedURI.encrypt({
   content: 'secret message',
   key: 'secret key'
});
// default algorithm is aes/cbc from webcrypto
// encrypted:?a24567b823f5c7918736194ab5c2e83d;rtyu...<cypher>

```