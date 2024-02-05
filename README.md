> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI
## URI Encrypted Scheme Specification

[![npm version](https://badge.fury.io/js/@encrypted-uri%2Fcore.svg)](https://github.com/antonioconselheiro/encrypted-uri)
[![Npm Total Downloads](https://img.shields.io/npm/dt/@encrypted-uri/core.svg)](https://github.com/antonioconselheiro/encrypted-uri)
[![Npm Monthly Downloads](https://img.shields.io/npm/dm/@encrypted-uri/core.svg)](https://github.com/antonioconselheiro/encrypted-uri)

Encode to identify different types of encrypted content into a URI allowing the user to customize his ciphers with his preferred encryption algorithm.

## Run example
[Open example app](https://antonioconselheiro.github.io/encrypted-uri/ciphers-example/browser/)

## Installation

```npm install @encrypted-uri/core --save```

The core will provide you with the main tools to interpret an Encrypted URI and to direct the content to the correct decryption algorithm, but the core does not include any algorithm, you will need to install this separately.

```npm install @encrypted-uri/ciphers --save```

## Purpose

The purpose of Encrypted URI is to be used to storage ciphered content in a qrcode. Through this encode it is possible to represent an encryption cipher with its main parameters in a lean way (to generate less dense qrcodes).

Encryption keys, private document signing keys and wallet seeds are examples of extremely sensitive information, which leads to a demand not to store them digitally, but physically and encrypted.

This tool is mainly proposed for encryption algorithms that can be decrypted with a key, but other types of algorithms can be supported if needed.

The encode allows customize your app defaults params for encryptation, you can also allow your user customize the algorithm in which he will store the information in his custody.

## Syntax
Encrypted URI are composed of five parts:

```encrypted:[algorithm][?[args]];[cipher]```

The ```encrypted``` keyword identifies the string as encrypted uri.

The ```algorithm``` is the algorithm name, if not set, ```aes/cbc``` MUST be  assumed. The ```mode``` is separatted from algorithm name by a bar, like ```aes/cbc```. If the algorithm is set just as ```aes```, the operation mode MUST be  assumed as CBC.

The ```args``` are query string format arguments with values encoded into percent-encoded. If the algorithm requires one single mandatory argument, when this argument is send alone in ```args``` it's not needed to include the attribute name.

The ```cipher``` is the cipher or cipher params in a [OpenSSL compatible string](https://www.openssl.org/docs/man1.0.2/man1/openssl-enc.html), the salt param are sent in the header Salted_ in the bytes.

## Example
The default, with default values ignored:
```encrypted:?249c3d09119;U2FsdGVkX1mxOv5WpmRGHXZouip==```

With all parameters include:
```encrypted:aes/cbc?iv=249c3d09119&pad=pkcs%237;U2FsdGVkX1mxOv5WpmRGHXZouip```

Customized:
```encrypted:aes?iv=249c3d09119;U2FsdGVkX1mxOv5WpmRGHXZouip```

Algorithm with no param:
```encrypted:aes/ecb;U2FsdGVkX1mxOv5WpmRGHXZouip```

## How to use
Basic use, how to decode and encrypt and how to decode and decrypt: 

```typescript
import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIResultset, TURIParams } from '@encrypted-uri/core';
import { ecb } from '@noble/ciphers/aes';
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';

class EncryptedURIAESECBDecrypter<T extends TURIParams = TURIParams> extends EncryptedURIDecrypter<T> {
  constructor(
    decoded: TEncryptedURI<T>,
    password: string,
    defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    super(decoded, password, defaultsKDF);
  }

  async decrypt(): Promise<string> {
    const cipher = base64.decode(this.decoded.cipher || '');
    const params = getSalt(cipher, this.decoded?.params);
    const result = await ecb(kdf(this.password, params.salt, this.decoded))
      .decrypt(params.cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ecb',
  decrypter: EncryptedURIAESECBDecrypter
})
class EncryptedURIAESECBEncrypter<T extends TURIParams = TURIParams> extends EncryptedURIEncrypter<TURIParams> {

  constructor(
    protected override params: TEncryptedURIResultset<T>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<T>> {
    const content = utf8ToBytes(this.params.content);
    const saltLength = 8;
    const salt = randomBytes(saltLength);
    const rawCipher = await ecb(kdf(this.params.password, salt, this.params.kdf)).encrypt(content);
    const cipher = base64.encode(OpenSSLSerializer.encode(rawCipher, salt));

    return Promise.resolve({ cipher });
  }
}

```

Advanced use, how to add default encrypter and how to add more alias to an algorithm: 
```typescript
import { EncryptedURI, EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIResultset } from '@encrypted-uri/core';
import { bytesToUtf8, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { cbc } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURI<TInitializationVectorParams>,
    password: string,
    defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    super(decoded, password, defaultsKDF);
  }

  async decrypt(): Promise<string> {
    const ivhex = getInitializationVector(this.decoded);
    const cipher = base64.decode(this.decoded.cipher);
    const params = getSalt(cipher, this.decoded?.params);

    const result = await cbc(kdf(this.password, params.salt, this.decoded), hexToBytes(ivhex))
      .decrypt(params.cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/cbc',
  decrypter: EncryptedURIAESCBCDecrypter
})
class EncryptedURIAESCBCEncrypter extends EncryptedURIEncrypter<TInitializationVectorParams> {

  constructor(
    protected override params: TEncryptedURIResultset<TInitializationVectorParams>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<TInitializationVectorParams>> {
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const saltLength = 8;
    const salt = randomBytes(saltLength);
    const cipher = await cbc(kdf(this.params.password, salt, this.params.kdf), iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(OpenSSLSerializer.encode(cipher, salt)),
      params: { iv: ivhex }
    });
  }
}

EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
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
