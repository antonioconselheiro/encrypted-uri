import { EncryptedURIAlgorithm, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { TEncryptedURIAESWithNumberOnceParams, getNumberOnce } from "aes/number-once";
import { siv } from '@noble/ciphers/aes';
import { base64 } from "@scure/base";

class EncryptedURIAESSIVDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithNumberOnceParams> {
  constructor(
    decoded: TEncryptedURIAESWithNumberOnceParams,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const nonce = getNumberOnce(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await siv(key, Uint8Array.from(base64.decode(nonce)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/siv',
  decrypter: EncryptedURIAESSIVDecrypter
})
class EncryptedURIAESSIVEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await siv(this.params.key, nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { no: numberOnceHex }
    });
  }
}
