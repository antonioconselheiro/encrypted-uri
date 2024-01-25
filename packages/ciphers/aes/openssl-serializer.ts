export class OpenSSLSerializer {

  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  private static readonly saltedHeader = [0x53616c74, 0x65645f5f];

  static encode(cipher: Uint8Array, salt: Uint8Array): Uint8Array {
    return Uint8Array.from([
      ...this.saltedHeader,
      ...salt,
      ...cipher
    ]);
  }

  static decode(openssl: Uint8Array): {
    cipher: Uint8Array,
    salt?: Uint8Array
  } {
    const cipher = Array.from(openssl);
    if (openssl[0] === this.saltedHeader[0] && openssl[1] === this.saltedHeader[1]) {
      //  remove header
      const integerBytesLength = 2;
      cipher.splice(0, integerBytesLength);

      //  collect header data
      const salt = cipher.splice(0, integerBytesLength);
      return {
        salt: Uint8Array.from(salt),
        cipher: Uint8Array.from(cipher)
      }
    }

    return {
      cipher: Uint8Array.from(cipher)
    };
  }
}
