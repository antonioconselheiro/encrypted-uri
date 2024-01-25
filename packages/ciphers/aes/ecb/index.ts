import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIResultset, TURIParams } from '@encrypted-uri/core';
import { ecb } from '@noble/ciphers/aes';
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { kdf } from '../kdf';
import { getSalt } from '../salt';
import { OpenSSLSerializer } from '../openssl-serializer';

class EncryptedURIAESECBDecrypter<T extends TURIParams = TURIParams> extends EncryptedURIDecrypter<T> {
  constructor(
    decoded: TEncryptedURI<T>,
    password: string,
    defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    super(decoded, password, defaultsKDF);
  }

  async decrypt(): Promise<string> {
    const cipher = utf8ToBytes(this.decoded.cipher || '');
    const salt = getSalt(cipher, this.decoded?.params);
    const result = await ecb(kdf(this.password, salt, this.decoded))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ecb',
  decrypter: EncryptedURIAESECBDecrypter
})
// eslint-disable-next-line @typescript-eslint/no-unused-vars
class EncryptedURIAESECBEncrypter<T extends TURIParams = TURIParams> extends EncryptedURIEncrypter<TURIParams> {

  constructor(
    protected override params: TEncryptedURIResultset<T>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<T>> {
    const content = utf8ToBytes(this.params.content);
    const saltLength = 32;
    const salt = randomBytes(saltLength);
    const rawCipher = await ecb(kdf(this.params.password, salt, this.params.kdf)).encrypt(content);
    const cipher = base64.encode(OpenSSLSerializer.encode(rawCipher, salt));

    return Promise.resolve({ cipher });
  }
}
