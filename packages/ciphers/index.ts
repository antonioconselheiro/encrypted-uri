import { EncryptedURI, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { ecb, siv } from '@noble/ciphers/aes';
import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { cbc, ctr, gcm } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';
import { base64 } from "@scure/base";

type TEncryptedURIAESWithInitializationVectorParams = TEncryptedURI<{ iv: string }>;
type TEncryptedURIAESWithNumberOnceParams = TEncryptedURI<{ no: string }>;

function getInitializationVector(args: TEncryptedURIAESWithInitializationVectorParams | undefined): string {
  return args?.params?.iv || args?.queryString || bytesToHex(randomBytes(16));
}

function getNumberOnce(args: TEncryptedURIAESWithNumberOnceParams | undefined): string {
  return args?.params?.no || args?.queryString || bytesToHex(randomBytes(12));
}

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
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
    const result = await cbc(key, hexToBytes(ivhex))
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
    const key = utf8ToBytes(this.params.key);
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await cbc(key, iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { iv: ivhex }
    });
  }
}

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
    const key = utf8ToBytes(this.params.key);
    const ivhex = getInitializationVector(this.params);
    const iv = hexToBytes(ivhex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await ctr(key, iv).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { iv: ivhex }
    });
  }
}

class EncryptedURIAESECBDecrypter extends EncryptedURIDecrypter<TEncryptedURI> {
  constructor(
    decoded: TEncryptedURI,
    private key: string
  ) {
    super(decoded);
  }

  async decrypt(): Promise<string> {
    const key = utf8ToBytes(this.key);
    const cipher = utf8ToBytes(this.decoded.cipher || '');
    const result = await ecb(key).decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/ecb',
  decrypter: EncryptedURIAESECBDecrypter
})
class EncryptedURIAESECBEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURI
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const content = utf8ToBytes(this.params.content);
    const rawCipher = await ecb(key).encrypt(content);
    const cipher = base64.encode(rawCipher);

    return Promise.resolve({ cipher });
  }
}

class EncryptedURIAESGCMDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithNumberOnceParams> {
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
    const result = await gcm(key, Uint8Array.from(base64.decode(nonce)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

@EncryptedURIAlgorithm({
  algorithm: 'aes/gcm',
  decrypter: EncryptedURIAESGCMDecrypter
})
class EncryptedURIAESGCMEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await gcm(key, nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { no: numberOnceHex }
    });
  }
}

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
    const result = await cbc(key, Uint8Array.from(base64.decode(nonce)))
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
    const key = utf8ToBytes(this.params.key);
    const numberOnceHex = getNumberOnce(this.params);
    const nonce = hexToBytes(numberOnceHex);
    const content = utf8ToBytes(this.params.content);
    const cipher = await siv(key, nonce).encrypt(content);

    return Promise.resolve({
      cipher: base64.encode(cipher),
      params: { no: numberOnceHex }
    });
  }
}

export function supportAES(): void {
  EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
}
