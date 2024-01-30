import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIResultset } from "@encrypted-uri/core";
import { siv } from '@noble/ciphers/aes';
import { bytesToUtf8, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from "@noble/hashes/utils";
import { base64 } from '@scure/base';
import { kdf } from "../kdf";
import { OpenSSLSerializer } from "../openssl-serializer";
import { getSalt } from "../salt";
import { TNumberOnceParams, getNumberOnce } from '../number-once';

class EncryptedURIAESSIVDecrypter extends EncryptedURIDecrypter<TNumberOnceParams> {
  constructor(
    decoded: TEncryptedURI<TNumberOnceParams>,
    password: string,
    defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    super(decoded, password, defaultsKDF);
  }

  async decrypt(): Promise<string> {
    const nonce = getNumberOnce(this.decoded);
    const cipher = base64.decode(this.decoded.cipher);
    const salt = getSalt(cipher, this.decoded?.params);
    const result = await siv(kdf(this.password, salt, this.decoded), hexToBytes(nonce))
      .decrypt(cipher);

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
    protected override params: TEncryptedURIResultset<TNumberOnceParams>
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<TNumberOnceParams>> {
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const saltLength = 32;
    const salt = randomBytes(saltLength);
    const cipher = await siv(kdf(this.params.password, salt, this.params.kdf), nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(OpenSSLSerializer.encode(cipher, salt)),
      params: { no: numberOnceHex }
    });
  }
}
