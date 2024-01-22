import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIResultset } from '@encrypted-uri/core';
import { bytesToUtf8, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { gcm } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { kdf } from 'aes/kdf';
import { getSalt } from 'aes/salt';
import { TNumberOnceParams, getNumberOnce } from '../number-once';

class EncryptedURIAESGCMDecrypter extends EncryptedURIDecrypter<TNumberOnceParams> {
  constructor(
    decoded: TEncryptedURI<TNumberOnceParams>,
    password: string,
    defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    super(decoded, password, defaultsKDF);
  }

  async decrypt(): Promise<string> {
    const nonce = getNumberOnce(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const salt = getSalt(cipher, this.decoded?.params);
    const result = await gcm(kdf(this.password, salt, this.decoded), Uint8Array.from(base64.decode(nonce)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/gcm',
  decrypter: EncryptedURIAESGCMDecrypter
})
class EncryptedURIAESGCMEncrypter extends EncryptedURIEncrypter<TNumberOnceParams> {

  constructor(
    protected override params: TEncryptedURIResultset<TNumberOnceParams>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<TNumberOnceParams>> {
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const salt = randomBytes(32);
    const cipher = await gcm(kdf(this.params.password, salt, this.params.kdf), nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { no: numberOnceHex }
    });
  }
}
