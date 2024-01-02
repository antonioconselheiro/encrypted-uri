import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, URIEncrypted, URIEncryptedDecrypter, URIEncryptedEncrypter } from "@encrypted-uri/core";
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

class URIEncryptedAESCBCEncrypter extends URIEncryptedEncrypter {

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

class URIEncryptedAESCBCDecrypter extends URIEncryptedDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
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

class URIEncryptedAESCTREncrypter extends URIEncryptedEncrypter {

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

class URIEncryptedAESCTRDecrypter extends URIEncryptedDecrypter<TEncryptedURIAESWithInitializationVectorParams> {
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

class URIEncryptedAESECBEncrypter extends URIEncryptedEncrypter {

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

class URIEncryptedAESECBDecrypter extends URIEncryptedDecrypter<TEncryptedURI> {
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

class URIEncryptedAESGCMEncrypter extends URIEncryptedEncrypter {

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

class URIEncryptedAESSIVDecrypter extends URIEncryptedDecrypter<TEncryptedURIAESWithNumberOnceParams> {
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

class URIEncryptedAESSIVEncrypter extends URIEncryptedEncrypter {

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

class URIEncryptedAESGCMDecrypter extends URIEncryptedDecrypter<TEncryptedURIAESWithNumberOnceParams> {
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

export function loadAES(): void {
  URIEncrypted.setAlgorithm('', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
  URIEncrypted.setAlgorithm('aes', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
  URIEncrypted.setAlgorithm('aes/cbc', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
  URIEncrypted.setAlgorithm('aes/ebc', URIEncryptedAESECBEncrypter, URIEncryptedAESECBDecrypter);
  URIEncrypted.setAlgorithm('aes/ctr', URIEncryptedAESCTREncrypter, URIEncryptedAESCTRDecrypter);
  URIEncrypted.setAlgorithm('aes/gcm', URIEncryptedAESGCMEncrypter, URIEncryptedAESGCMDecrypter);
  URIEncrypted.setAlgorithm('aes/siv', URIEncryptedAESSIVEncrypter, URIEncryptedAESSIVDecrypter);
}
