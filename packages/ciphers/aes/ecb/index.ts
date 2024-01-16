import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams, URIParams } from '@encrypted-uri/core';
import { ecb } from '@noble/ciphers/aes';
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { kdf } from 'aes/kdf';
import { OpenSSLSerializer } from 'aes/openssl-serializer';
import { getSalt } from 'aes/salt';

class EncryptedURIAESECBDecrypter<T extends URIParams = URIParams> extends EncryptedURIDecrypter<T> {
  constructor(
    decoded: TEncryptedURI<T>,
    private password: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const cipher = utf8ToBytes(this.decoded.cipher || '');
    const salt = getSalt(OpenSSLSerializer.decode(cipher), this.decoded?.params);
    const result = await ecb(kdf(this.password, salt))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ecb',
  decrypter: EncryptedURIAESECBDecrypter
})
class EncryptedURIAESECBEncrypter<T extends URIParams = URIParams> extends EncryptedURIEncrypter<URIParams> {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURI<T>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<T>> {
    const content = utf8ToBytes(this.params.content);
    const salt = randomBytes(32);
    const rawCipher = await ecb(kdf(this.params.password, salt)).encrypt(content);
    const cipher = base64.encode(rawCipher);

    return Promise.resolve({ cipher });
  }
}
