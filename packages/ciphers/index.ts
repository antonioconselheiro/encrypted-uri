import { EncryptedURI, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { ecb, siv } from '@noble/ciphers/aes';
import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { cbc, ctr, gcm } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';
import { base64 } from "@scure/base";

type TEncryptedURIAESWithInitializationVectorParams = TEncryptedURI<{ iv: string }>;
type TEncryptedURIAESWithNumberOnceParams = TEncryptedURI<{ no: string }>;

function getInitializationVector(args: TEncryptedURIAESWithInitializationVectorParams | undefined): string {
  return args?.params?.iv || args?.queryString || bytesToHex(randomBytes(16));
}

function getNumberOnce(args: TEncryptedURIAESWithNumberOnceParams | undefined): string {
  return args?.params?.no || args?.queryString || bytesToHex(randomBytes(12));
}

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURIAESWithInitializationVectorParams,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const ivhex = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await cbc(key, hexToBytes(ivhex))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/cbc',
  decrypter: EncryptedURIAESCBCDecrypter
})
class EncryptedURIAESCBCEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await cbc(key, iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { iv: ivhex }
    });
  }
}

class EncryptedURIAESCTRDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURIAESWithInitializationVectorParams,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const ivhex = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await ctr(key, hexToBytes(ivhex))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ctr',
  decrypter: EncryptedURIAESCTRDecrypter
})
class EncryptedURIAESCTREncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await ctr(key, iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { iv: ivhex }
    });
  }
}

class EncryptedURIAESECBDecrypter extends EncryptedURIDecrypter<TEncryptedURI> {
  constructor(
    decoded: TEncryptedURI,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const cipher = utf8ToBytes(this.decoded.cipher || '');
    const result = await ecb(key).decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ecb',
  decrypter: EncryptedURIAESECBDecrypter
})
class EncryptedURIAESECBEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURI
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const content = utf8ToBytes(this.params.content);
    const rawCipher = await ecb(key).encrypt(content);
    const cipher = base64.encode(rawCipher);

    return Promise.resolve({ cipher });
  }
}

class EncryptedURIAESGCMDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithNumberOnceParams> {
  constructor(
    decoded: TEncryptedURIAESWithNumberOnceParams,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const nonce = getNumberOnce(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await gcm(key, Uint8Array.from(base64.decode(nonce)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/gcm',
  decrypter: EncryptedURIAESGCMDecrypter
})
class EncryptedURIAESGCMEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await gcm(key, nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { no: numberOnceHex }
    });
  }
}

class EncryptedURIAESSIVDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithNumberOnceParams> {
  constructor(
    decoded: TEncryptedURIAESWithNumberOnceParams,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const nonce = getNumberOnce(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await cbc(key, Uint8Array.from(base64.decode(nonce)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/siv',
  decrypter: EncryptedURIAESSIVDecrypter
})
class EncryptedURIAESSIVEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await siv(key, nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { no: numberOnceHex }
    });
  }
}

export function supportAES(): void {
  EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
}

/**
 * This class was orignally write in javascript for crypt-js, I'm uncluding this to my lib
 * https://github.com/brix/crypto-js/blob/develop/src/cipher-core.js#L566
 * OpenSSL formatting strategy.
 */
export class OpenSSL {
  /**
   * Converts a cipher params object to an OpenSSL-compatible string.
   *
   * @param {CipherParams} cipherParams The cipher params object.
   *
   * @return {string} The OpenSSL-compatible string.
   *
   * @static
   *
   * @example
   *
   *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
   */
  static stringify(cipherParams): string {
      var wordArray;

      // Shortcuts
      var ciphertext = cipherParams.ciphertext;
      var salt = cipherParams.salt;

      // Format
      if (salt) {
          wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
      } else {
          wordArray = ciphertext;
      }

      return wordArray.toString(Base64);
  }

  /**
   * Converts an OpenSSL-compatible string to a cipher params object.
   *
   * @param {string} openSSLStr The OpenSSL-compatible string.
   *
   * @return {CipherParams} The cipher params object.
   *
   * @static
   *
   * @example
   *
   *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
   */
  static parse(openSSLStr) {
      var salt;

      // Parse base64
      var ciphertext = Base64.parse(openSSLStr);

      // Shortcut
      var ciphertextWords = ciphertext.words;

      // Test for salt
      if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
          // Extract salt
          salt = WordArray.create(ciphertextWords.slice(2, 4));

          // Remove salt from ciphertext
          ciphertextWords.splice(0, 4);
          ciphertext.sigBytes -= 16;
      }

      return CipherParams.create({ ciphertext: ciphertext, salt: salt });
  }
};