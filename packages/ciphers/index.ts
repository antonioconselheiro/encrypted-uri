import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, EncryptedURI, EncryptedURIDecrypter, EncryptedURIEncrypter } from "@encrypted-uri/core";
import { cbc, ecb, ctr, gcm, siv } from '@noble/ciphers/aes';
import { utf8ToBytes } from "@noble/ciphers/utils";


type TEncryptedURIAESWithInitializationVectorParams = TEncryptedURI<{ iv: string }>;
type TEncryptedURIAESWithNumberOnceParams = TEncryptedURI<{ no: string }>;

function getInitializationVector(encryptedUriDecoded: TEncryptedURIAESWithInitializationVectorParams | undefined): string {
  return encryptedUriDecoded?.params?.iv || encryptedUriDecoded?.queryString || '';
}

function getNumberOnce(encryptedUriDecoded: TEncryptedURIAESWithNumberOnceParams | undefined): string {
  return encryptedUriDecoded?.params?.no || encryptedUriDecoded?.queryString || '';
}

class EncryptedURIAESCBCEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const key = utf8ToBytes(this.params.key);
    const iv = getInitializationVector(this.params);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/cbc',
      cypher: cbc(key, utf8ToBytes(iv))
        .encrypt(content)
        .toString(),
      params: { iv }
    };
  }
}

class EncryptedURIAESCBCDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURIAESWithInitializationVectorParams,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const key = utf8ToBytes(this.key);
    const iv = utf8ToBytes(getInitializationVector(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher);

    return cbc(key, iv)
      .decrypt(cypher)
      .toString();
  }
}

class EncryptedURIAESCTREncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const key = utf8ToBytes(this.params.key);
    const iv = getInitializationVector(this.params);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/ctr',
      cypher: ctr(key, utf8ToBytes(iv))
        .encrypt(content)
        .toString(),
      params: { iv }
    };
  }
}

class EncryptedURIAESCTRDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
  constructor(
    decoded: TEncryptedURIAESWithInitializationVectorParams,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const key = utf8ToBytes(this.key);
    const iv = utf8ToBytes(getInitializationVector(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher || '');

    return ctr(key, iv)
      .decrypt(cypher)
      .toString();
  }
}

class EncryptedURIAESECBEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURI
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const key = utf8ToBytes(this.params.key);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/ecb',
      cypher: ecb(key)
        .encrypt(content)
        .toString()
    };
  }
}

class EncryptedURIAESECBDecrypter extends EncryptedURIDecrypter<TEncryptedURI> {
  constructor(
    decoded: TEncryptedURI,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const key = utf8ToBytes(this.key);
    const cypher = utf8ToBytes(this.decoded.cypher || '');

    return ecb(key)
      .decrypt(cypher)
      .toString();
  }
}

class EncryptedURIAESGCMEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const key = utf8ToBytes(this.params.key);
    const nonce = getNumberOnce(this.params);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/gcm',
      cypher: gcm(key, utf8ToBytes(nonce))
        .encrypt(content)
        .toString(),
      params: { no: nonce }
    };
  }
}

class EncryptedURIAESSIVDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithNumberOnceParams> {
  constructor(
    decoded: TEncryptedURIAESWithNumberOnceParams,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const key = utf8ToBytes(this.key);
    const nonce = utf8ToBytes(getNumberOnce(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher);

    return siv(key, nonce)
      .decrypt(cypher)
      .toString();
  }
}

class EncryptedURIAESSIVEncrypter extends EncryptedURIEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithNumberOnceParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const key = utf8ToBytes(this.params.key);
    const nonce = getNumberOnce(this.params);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/gcm',
      cypher: siv(key, utf8ToBytes(nonce))
        .encrypt(content)
        .toString(),
      params: { no: nonce }
    };
  }
}

class EncryptedURIAESGCMDecrypter extends EncryptedURIDecrypter<TEncryptedURIAESWithNumberOnceParams> {
  constructor(
    decoded: TEncryptedURIAESWithNumberOnceParams,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const key = utf8ToBytes(this.key);
    const nonce = utf8ToBytes(getNumberOnce(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher);

    return gcm(key, nonce)
      .decrypt(cypher)
      .toString();
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
