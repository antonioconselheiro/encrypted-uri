import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIResultset, TURIParams } from '@encrypted-uri/core';
import { ecb } from '@noble/ciphers/aes';
import { bytesToUtf8, utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { kdf } from '../../kdf';
import { OpenSSLSerializer } from '../../openssl-serializer';
import { getSalt } from '../../salt';

class EncryptedURIAESECBDecrypter<T extends TURIParams = TURIParams> extends EncryptedURIDecrypter<T> {
  constructor(
    decoded: TEncryptedURI<T>,
    password: string
  ) {
    super(decoded, password);
  }

  async decrypt(): Promise<string> {
    const cipher = base64.decode(this.decoded.cipher || '');
    const params = getSalt(cipher, this.decoded?.params);
    const derivatedKey = kdf(this.password, params.salt, this.decoded);
    const result = await ecb(derivatedKey)
      .decrypt(params.cipher);

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
    params: TEncryptedURIResultset<T>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<T>> {
    const content = utf8ToBytes(this.params.content);
    const saltLength = 8;
    const salt = randomBytes(saltLength);
    const derivatedKey = kdf(this.params.password, salt, this.params);
    const rawCipher = await ecb(derivatedKey).encrypt(content);
    const cipher = base64.encode(OpenSSLSerializer.encode(rawCipher, salt));

    return Promise.resolve({ cipher });
  }
}
