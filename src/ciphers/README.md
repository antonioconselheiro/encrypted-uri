> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI - ciphers
Include AES algorithms from @noble/ciphers into Encrypted URI (@encrypted-uri/core). Only ```initialization vector``` and ```number once``` params are included.

*under beta test*

## Installation

```npm install @encrypted-uri/ciphers --save```

```typescript
import { EncryptedURI } from '@encrypted-uri/core';
import { loadAES } from '@encrypted-uri/ciphers';

EncryptedURI.encrypt({
   algorithm: 'aes/cbc',
   params: { iv: '12345678' }
}, 'secret key');
```