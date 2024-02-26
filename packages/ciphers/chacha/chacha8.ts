import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIResultset } from '@encrypted-uri/core';
import { chacha8 } from '@noble/ciphers/chacha';
import { TNumberOnceParams, getNumberOnce } from '../number-once';
import { hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import { kdf } from '../kdf';
import { OpenSSLSerializer } from '../openssl-serializer';
import { base64 } from '@scure/base';
import { getSalt } from '../salt';

class EncryptedURIAESSIVDecrypter extends EncryptedURIDecrypter<TNumberOnceParams> {
    constructor(
      decoded: TEncryptedURI<TNumberOnceParams>,
      password: string
    ) {
      super(decoded, password);
    }
  
    async decrypt(): Promise<string> {
      const nonce = getNumberOnce(this.decoded);
      const cipher = base64.decode(this.decoded.cipher);
      const params = getSalt(cipher, this.decoded?.params);
      const derivatedKey = kdf(this.password, params.salt, this.decoded);
      const result = await chacha8(derivatedKey, hexToBytes(nonce))
        .decrypt(params.cipher);
  
      return bytesToUtf8(result);
    }
  }
  
  @EncryptedURIAlgorithm({
    algorithm: 'aes/siv',
    decrypter: EncryptedURIAESSIVDecrypter
  })
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  class EncryptedURIAESSIVEncrypter extends EncryptedURIEncrypter<TNumberOnceParams> {
  
    constructor(
      params: TEncryptedURIResultset<TNumberOnceParams>
    ) {
      super(params);
    }
  
    async encrypt(): Promise<TEncryptedURI<TNumberOnceParams>> {
      const numberOnceHex = getNumberOnce(this.params);
      const nonce = hexToBytes(numberOnceHex);
      const content = utf8ToBytes(this.params.content);
      const saltLength = 8;
      const salt = randomBytes(saltLength);
      const derivatedKey = kdf(this.params.password, salt, this.params);
      const cipher = await chacha8(derivatedKey, nonce, content);
  
      return Promise.resolve({
        cipher: base64.encode(OpenSSLSerializer.encode(cipher, salt)),
        params: { no: numberOnceHex }
      });
    }
  }
  