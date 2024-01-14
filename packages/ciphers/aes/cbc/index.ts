import { EncryptedURI, EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from '@encrypted-uri/core';
import { bytesToUtf8, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { base64 } from '@scure/base';
import { cbc } from '@noble/ciphers/webcrypto/aes';
import { TEncryptedURIAESWithInitializationVectorParams, getInitializationVector } from '../initialization-vector';
import { OpenSSLSerializer } from 'aes/openssl-serializer';
import { randomBytes } from '@noble/hashes/utils';
import { kdf } from 'aes/kdf';
import { getSalt } from 'aes/salt';

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURIAESWithInitializationVectorParams,
    private password: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const ivhex = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const salt = getSalt(OpenSSLSerializer.decode(cipher), this.decoded?.params);
    const result = await cbc(kdf(this.password, salt), hexToBytes(ivhex))
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
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const salt = randomBytes(32);
    const cipher = await cbc(kdf(this.params.password, salt), iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(OpenSSLSerializer.encode(cipher, salt)),
      params: { iv: ivhex }
    });
  }
}

EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
