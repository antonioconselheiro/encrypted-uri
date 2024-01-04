import { EncryptedURI, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { ecb, siv } from '@noble/ciphers/aes';
import { bytesToUtf8, utf8ToBytes } from "@noble/ciphers/utils";
import { cbc, ctr, gcm } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';
import { base64 } from "@scure/base";

type TEncryptedURIAESWithInitializationVectorParams = TEncryptedURI<{ iv: string }>;
type TEncryptedURIAESWithNumberOnceParams = TEncryptedURI<{ no: string }>;

function getInitializationVector(args: TEncryptedURIAESWithInitializationVectorParams | undefined): string {
  return args?.params?.iv || args?.queryString || base64.encode(randomBytes(12));
}

function getNumberOnce(args: TEncryptedURIAESWithNumberOnceParams | undefined): string {
  return args?.params?.no || args?.queryString || base64.encode(randomBytes(16));
}

class EncryptedURIAESCBCEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const ivb64 = getInitializationVector(this.params);
    const iv = Uint8Array.from(base64.decode(ivb64));
    const content = utf8ToBytes(this.params.content);
    const cipher = await cbc(key, iv).encrypt(content);

    return Promise.resolve({
      algorithm: 'aes/cbc',
      cipher: base64.encode(cipher),
      params: { iv: ivb64 }
    });
  }
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
    const ivb64 = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await cbc(key, Uint8Array.from(base64.decode(ivb64)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

class EncryptedURIAESCTREncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const ivb64 = getInitializationVector(this.params);
    const iv = Uint8Array.from(base64.decode(ivb64));
    const content = utf8ToBytes(this.params.content);
    const cipher = await ctr(key, iv).encrypt(content);

    return Promise.resolve({
      algorithm: 'aes/ctr',
      cipher: base64.encode(cipher),
      params: { iv: ivb64 }
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
    const ivb64 = getInitializationVector(this.decoded);
    const cipher = utf8ToBytes(this.decoded.cipher);
    const result = await ctr(key, Uint8Array.from(base64.decode(ivb64)))
      .decrypt(cipher);

    return bytesToUtf8(result);
  }
}

class EncryptedURIAESECBEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURI
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const content = utf8ToBytes(this.params.content);
    const cipher = await ecb(key).encrypt(content);

    return Promise.resolve({
      algorithm: 'aes/ecb',
      cipher: base64.encode(cipher)
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

class EncryptedURIAESGCMEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const nonceBase64 = getNumberOnce(this.params);
    const nonce = Uint8Array.from(base64.decode(nonceBase64));
    const content = utf8ToBytes(this.params.content);
    const cipher = await gcm(key, nonce).encrypt(content);

    return Promise.resolve({
      algorithm: 'aes/gcm',
      cipher: base64.encode(cipher),
      params: { no: nonceBase64 }
    });
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

class EncryptedURIAESSIVEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  async encrypt(): Promise<TEncryptedURI> {
    const key = utf8ToBytes(this.params.key);
    const nonceBase64 = getNumberOnce(this.params);
    const nonce = Uint8Array.from(base64.decode(nonceBase64));
    const content = utf8ToBytes(this.params.content);
    const cipher = await siv(key, nonce).encrypt(content);

    return Promise.resolve({
      algorithm: 'aes/siv',
      cipher: base64.encode(cipher),
      params: { no: nonceBase64 }
    });
  }
}

export function supportAES(): void {
  EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm('aes/cbc', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm('aes/ebc', EncryptedURIAESECBEncrypter, EncryptedURIAESECBDecrypter);
  EncryptedURI.setAlgorithm('aes/ctr', EncryptedURIAESCTREncrypter, EncryptedURIAESCTRDecrypter);
  EncryptedURI.setAlgorithm('aes/gcm', EncryptedURIAESGCMEncrypter, EncryptedURIAESGCMDecrypter);
  EncryptedURI.setAlgorithm('aes/siv', EncryptedURIAESSIVEncrypter, EncryptedURIAESSIVDecrypter);
}
