> "He that hath an ear, let him hear what the Spirit saith unto the churches; To him that overcometh will I give to eat of the hidden
> manna, and will give him a white stone, and in the stone a new name written, which no man knoweth saving he that receiveth it."
> Apocalypse 2:17

# Encrypted URI
## Generic Encrypted Content Encode Specification

Encode to standardize different types of encrypted content into a query string that allows the user to customize his cyphers with his preferred encryption algorithm.

## Syntax
Encrypted URI are composed of four parts: a prefix (encrypted:), the algorithm name indicating the type of encrypted data, a set of parameters that may vary depending on the type of encryption selected, and the cypher itself.

```encrypted:[algorithm]?[args];[cypher]```

Example:
```encrypted:aes?iv=249704f119c3d09e4e0fb3b6a275e519;U2FsdGVkX1/mxOv5WpmRGHXZouip6GOw+P+Jdks6c1Z/uMfwBl7Me+dzJjioF72z9E+bKY/GlcL8HlWnWrs7fTlqVvzmsC3b2dm+JfL2rTH+60dNlk6PJ+41pLRDWA/l```

## Example of practical use:
 - [Private QRcode](https://antonioconselheiro.github.io/private-qrcode/#/home), allow you to create private qrcode using encrypted URI with AES algorithm fixed in it. It allow you to save your seeds, nsec and keys physically printed.

## References:
https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs
