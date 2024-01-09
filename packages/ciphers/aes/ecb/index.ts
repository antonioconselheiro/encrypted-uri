import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from '@encrypted-uri/core';
import { ecb } from '@noble/ciphers/aes';
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
import { base64 } from '@scure/base';

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
    const content = utf8ToBytes(this.params.content);
    const rawCipher = await ecb(this.params.key).encrypt(content);
    const cipher = base64.encode(rawCipher);

    return Promise.resolve({ cipher });
  }
}
