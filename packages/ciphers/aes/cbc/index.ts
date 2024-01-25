import { EncryptedURI, EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIResultset } from '@encrypted-uri/core';
import { bytesToUtf8, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { cbc } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { TInitializationVectorParams, getInitializationVector } from '../initialization-vector';
import { kdf } from '../kdf';
import { OpenSSLSerializer } from '../openssl-serializer';
import { getSalt } from '../salt';

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURI<TInitializationVectorParams>,
    password: string,
    defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    super(decoded, password, defaultsKDF);
  }

  async decrypt(): Promise<string> {
    const ivhex = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const salt = getSalt(cipher, this.decoded?.params);
    const result = await cbc(kdf(this.password, salt, this.decoded), hexToBytes(ivhex))
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
    const saltLength = 32;
    const salt = randomBytes(saltLength);
    const cipher = await cbc(kdf(this.params.password, salt, this.params.kdf), iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(OpenSSLSerializer.encode(cipher, salt)),
      params: { iv: ivhex }
    });
  }
}

EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
