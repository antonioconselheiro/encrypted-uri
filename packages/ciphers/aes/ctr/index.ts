import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { InitializationVectorParams, TEncryptedURIAESWithInitializationVectorParams, getInitializationVector } from "../initialization-vector";
import { ctr } from '@noble/ciphers/webcrypto/aes';
import { base64 } from "@scure/base";
import { OpenSSLSerializer } from "aes/openssl-serializer";
import { getSalt } from "aes/salt";
import { kdf } from "aes/kdf";
import { randomBytes } from "@noble/hashes/utils";

class EncryptedURIAESCTRDecrypter extends EncryptedURIDecrypter<InitializationVectorParams> {
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
    const result = await ctr(kdf(this.password, salt), hexToBytes(ivhex))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ctr',
  decrypter: EncryptedURIAESCTRDecrypter
})
class EncryptedURIAESCTREncrypter extends EncryptedURIEncrypter<InitializationVectorParams> {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI<InitializationVectorParams>> {
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const salt = randomBytes(32);
    const cipher = await ctr(kdf(this.params.password, salt), iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { iv: ivhex }
    });
  }
}
