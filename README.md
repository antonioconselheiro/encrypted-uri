> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden
> manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI
## URI Encrypted Scheme Specification

Encode to standardize different types of encrypted content into a query string that allows the user to customize his cyphers with his preferred encryption algorithm.

## Syntax
Encrypted URI are composed of four parts: a prefix (encrypted:), the algorithm name indicating the type of encrypted data, a set of parameters that may vary depending on the type of encryption selected, and the cypher itself.

```encrypted:[algorithm]?[args];[cypher]```

## Example:
With all parameters include:
```encrypted:aes/cbc?iv=249704f119c3d09e4e0fb3b6a275e519&pad=pkcs7;U2FsdGVkX1/mxOv5WpmRGHXZouip6GOw+P+Jdks6c1Z/uMfwBl7Me+dzJjioF72z9E+bKY/GlcL8HlWnWrs7fTlqVvzmsC3b2dm+JfL2rTH+60dNlk6PJ+41pLRDWA/l```

With default values ignored:
```encrypted:?249704f119c3d09e4e0fb3b6a275e519;U2FsdGVkX1/mxOv5WpmRGHXZouip6GOw+P+Jdks6c1Z/uMfwBl7Me+dzJjioF72z9E+bKY/GlcL8HlWnWrs7fTlqVvzmsC3b2dm+JfL2rTH+60dNlk6PJ+41pLRDWA/l```

Customized:
```encrypted:aes?iv=249704f119c3d09e4e0fb3b6a275e519;U2FsdGVkX1/mxOv5WpmRGHXZouip6GOw+P+Jdks6c1Z/uMfwBl7Me+dzJjioF72z9E+bKY/GlcL8HlWnWrs7fTlqVvzmsC3b2dm+JfL2rTH+60dNlk6PJ+41pLRDWA/l```

## Default value
Default encryptation is ```AES``` with ```CBC``` operation mode with the default web crypto api padding (padding scheme for block ciphers, ```PCKCS#7```, pkcs7).

If the arguments are not a query string, the content is assumed to be the value of the ```initialization vector``` for AES, if is not AES it will be assumed as ```nonce```

## Example of practical use:
 - [Private QRcode](https://antonioconselheiro.github.io/private-qrcode/#/home), allow you to create private qrcode using encrypted URI with AES algorithm fixed in it. It allow you to save your seeds, nsec and keys physically printed.

## Donate
Help me continue working on tools for the bitcoin and nostr universe, like this one. #zapthedev

There's still a lot of work to do.

Lighting donate: <a href="lightning:antonioconselheiro@getalby.com">lightning:antonioconselheiro@getalby.com</a>

![zap me](https://raw.githubusercontent.com/antonioconselheiro/antonioconselheiro/main/img/qrcode-wallet-lighting.png)

Bitcoin onchain donate: <a href="bitcoin:bc1qrm99lmmpwk7zsh7njpgthw87yvdm38j2lzpq7q">bc1qrm99lmmpwk7zsh7njpgthw87yvdm38j2lzpq7q</a>

![zap me](https://raw.githubusercontent.com/antonioconselheiro/antonioconselheiro/main/img/qrcode-wallet-bitcoin.png)

## Contribute
[CONTRIBUTE.md](./CONTRIBUTE.md)