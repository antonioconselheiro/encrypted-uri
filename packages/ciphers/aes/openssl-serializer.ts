import { bytesToHex } from "@noble/hashes/utils";

export class OpenSSLSerializer {

  // Salted__
  private static readonly saltedHeader = Uint8Array.from([
    0x53, 0x61, 0x6C, 0x74,
    0x65, 0x64, 0x5F, 0x5F
  ]);

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
    const longBytesLength = 8;
    const cipher = Array.from(openssl);

    if (
      bytesToHex(openssl.slice(0, longBytesLength)) === bytesToHex(this.saltedHeader)
    ) {
      //  remove header
      cipher.splice(0, longBytesLength);

      //  collect header data
      const salt = cipher.splice(0, longBytesLength);
      return {
        salt: Uint8Array.from(salt),
        cipher: Uint8Array.from(cipher)
      }
    }

    return {
      cipher: openssl
    };
  }
}
