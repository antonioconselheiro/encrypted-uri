import { EncryptedURI, EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIResultset } from '@encrypted-uri/core';
import { bytesToUtf8, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { cbc } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { kdf } from 'aes/kdf';
import { OpenSSLSerializer } from 'aes/openssl-serializer';
import { getSalt } from 'aes/salt';
import { TInitializationVectorParams, getInitializationVector } from '../initialization-vector';

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURI<TInitializationVectorParams>,
    private password: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const ivhex = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const salt = getSalt(cipher, this.decoded?.params);
    const result = await cbc(kdf(this.password, salt), hexToBytes(ivhex))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/cbc',
  decrypter: EncryptedURIAESCBCDecrypter
})
class EncryptedURIAESCBCEncrypter extends EncryptedURIEncrypter<TInitializationVectorParams> {

  constructor(
    protected override params: TEncryptedURIResultset<TInitializationVectorParams>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<TInitializationVectorParams>> {
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const salt = randomBytes(32);
    const cipher = await cbc(kdf(this.params.password, salt, this.params.kdf), iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(OpenSSLSerializer.encode(cipher, salt)),
      params: { iv: ivhex }
    });
  }
}

EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
