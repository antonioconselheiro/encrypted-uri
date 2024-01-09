import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { TEncryptedURIAESWithInitializationVectorParams, getInitializationVector } from "aes/initialization-vector";
import { ctr } from '@noble/ciphers/webcrypto/aes';
import { base64 } from "@scure/base";

class EncryptedURIAESCTRDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURIAESWithInitializationVectorParams,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const ivhex = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await ctr(key, hexToBytes(ivhex))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ctr',
  decrypter: EncryptedURIAESCTRDecrypter
})
class EncryptedURIAESCTREncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await ctr(this.params.key, iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { iv: ivhex }
    });
  }
}
