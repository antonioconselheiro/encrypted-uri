> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI
## URI Encrypted Scheme Specification

[![npm version](https://badge.fury.io/js/@encrypted-uri%2Fcore.svg)](https://github.com/antonioconselheiro/encrypted-uri)
[![Npm Total Downloads](https://img.shields.io/npm/dt/@encrypted-uri/core.svg)](https://github.com/antonioconselheiro/encrypted-uri)
[![Npm Monthly Downloads](https://img.shields.io/npm/dm/@encrypted-uri/core.svg)](https://github.com/antonioconselheiro/encrypted-uri)

*under beta test*

Encode to standardize different types of encrypted content into a URI that allows the user to customize his cyphers with his preferred encryption algorithm.

## Run example
[Open example app](https://antonioconselheiro.github.io/encrypted-uri/ciphers-example/browser/)

## Installation

```npm install @encrypted-uri/core --save```

The core will provide you with the main tools to interpret an Encrypted URI and to direct the content to the correct decryption algorithm, but the core does not include any algorithm, you will need to install this separately.

```npm install @encrypted-uri/ciphers --save```

## Purpose

The practical purpose for which the encrypted uri is specified and implemented is the storage of encrypted information in qrcode. Through this encode it is possible to represent an encryption cipher with its main parameters in a lean way (to generate less dense qrcodes).

Encryption keys, private document signing keys and wallet seeds are examples of extremely sensitive information, which leads to a demand not to store them digitally, but only physically and encrypted.

Its fundamental proposal proposes the use of the encode for algorithms that have the means of being decrypted with one or more opening keys, but nothing prevents transmitting other types of algorithms if this encode is a solution to this need.

The encode allows applications that use it to limit their support to a group or a single algorithm, but it also allows applications to provide the user with the option to customize the algorithm in which it will store the information in its custody.

The encode helps to receive updates to new algorithms, maintaining compatibility with previously used algorithms.

## Syntax
Encrypted URI are composed of five parts:

```encrypted:[algorithm][?[args]];[cypher]```

The ```encrypted``` keyword identifies the string as encrypted uri.

The ```algorithm``` is the algorithm name, if not set, ```aes/cbc``` MUST be  assumed. The ```mode``` is separatted from algorithm name by a bar, like ```aes/cbc```. If the algorithm is set just as ```aes```, the operation mode MUST be  assumed as CBC.

The ```args``` are query string format arguments with values encoded into percent-encoded. If the algorithm requires one single mandatory argument, when this argument is send alone in ```args``` it's not needed to include the attribute name.

The ```cypher``` is the cypher itself.

## Example
The default, with default values ignored:
```encrypted:?249c3d09119;U2FsdGVkX1mxOv5WpmRGHXZouip```

With all parameters include:
```encrypted:aes/cbc?iv=249c3d09119&pad=pkcs%237;U2FsdGVkX1mxOv5WpmRGHXZouip```

Customized:
```encrypted:aes?iv=249c3d09119;U2FsdGVkX1mxOv5WpmRGHXZouip```

Algorithm with no param:
```encrypted:aes/ecb;U2FsdGVkX1mxOv5WpmRGHXZouip```

## How to use
Basic use, how to decode and encrypt and how to decode and decrypt: 

```typescript
import { EncryptedURI } from '@encrypted-uri/core';

//  generates encrypted:aes?iv=1234567812345678;<cypher>
const encoded = EncryptedURI.encrypt({
  algorithm: 'aes',
  content: 'mensagem secreta',
  key: 'secretkey',
  params: {
    iv: '1234567812345678'
  }
});

//  check if it's and encrypted uri
if (EncryptedURI.matcher(encoded)) {
  //  decrypt
  EncryptedURI.decrypt(encoded, 'secretkey');
}

//  generates encrypted:?1234567812345678;<cypher>
EncryptedURI.encrypt({
  content: 'mensagem secreta',
  key: 'secretkey',
  queryString: '1234567812345678'
});

//  generates encrypted:aes/cbc?1234567812345678;<cypher>
EncryptedURI.encrypt({
  algorithm: 'aes',
  mode: 'cbc',
  content: 'mensagem secreta',
  key: 'secretkey',
  queryString: '1234567812345678'
});
```

Advanced use, how to add encrypters and decrypters: 
```typescript
import { algorithm } from 'algorithms';

class CustomDecrypter extends EncryptedDecrypterURI {

  constructor(
    decoded: TEncryptedURI,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    return algorithm.decrypt(this.decoded.cypher, this.key);
  }
}

class CustomEncrypter extends EncryptedEncrypterURI {
  constructor(
    params: TEncryptedURIEncryptableDefaultParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    return {
      algorithm: 'custom',
      cypher: algorithm.encrypt(this.decoded.cypher, this.key)
    };
  }
}

EncryptedURI.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
```

## Example of practical application
 - [Private QRcode](https://antonioconselheiro.github.io/private-qrcode/#/home), allow you to create private qrcode using encrypted URI with AES algorithm fixed in it. It allow you to save your seeds, nsec and keys physically printed.

## Contribute
[CONTRIBUTE.md](./CONTRIBUTE.md)

## Donate
Help me continue working on tools for the bitcoin and nostr universe, like this one. #zapthedev

There's still a lot of work to do.

Lighting donate: <a href="lightning:antonioconselheiro@getalby.com">lightning:antonioconselheiro@getalby.com</a>

![zap me](https://raw.githubusercontent.com/antonioconselheiro/antonioconselheiro/main/img/qrcode-wallet-lighting.png)

Bitcoin onchain donate: <a href="bitcoin:bc1qrm99lmmpwk7zsh7njpgthw87yvdm38j2lzpq7q">bc1qrm99lmmpwk7zsh7njpgthw87yvdm38j2lzpq7q</a>

![zap me](https://raw.githubusercontent.com/antonioconselheiro/antonioconselheiro/main/img/qrcode-wallet-bitcoin.png)
