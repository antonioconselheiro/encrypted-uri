import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, URIEncrypted, URIEncryptedDecrypter, URIEncryptedEncrypter } from "@encrypted-uri/core";
import { cbc, ecb, ctr, gcm, siv } from '@noble/ciphers/aes';
import { utf8ToBytes } from "@noble/ciphers/utils";

const supportedAlgorithmAes = {
  aes: 'aes'
};

const supportedAlgorithmChacha = {
  salsa20: 'salsa20',
  chacha: 'chacha',
  xsalsa20: 'xsalsa20',
  xchacha: 'xchacha',
  chacha8: 'chacha8',
  chacha12: 'chacha12',
  'xchacha20/poly1305': 'xchacha20/poly1305'
};

const supportedAlgorithm = {
  ...supportedAlgorithmAes,
  ...supportedAlgorithmChacha
};

const AESOperationMode = {
  cbc,
  ecb,
  ctr,
  gcm,
  siv
};

const AESPadding = {
  'pkcs#7': 'pkcs#7',
  'ansix.923': 'ansix.923',
  iso10126: 'iso10126',
  iso97971: 'iso97971',
  zeropadding: 'zeropadding',
  nopadding: 'nopadding'
};

const supportedAlgorithmList = Object.keys(supportedAlgorithm);
const AESOperationModeList = Object.keys(AESOperationMode);

type TEncryptedURISupportedChachaAlgorithm = keyof typeof supportedAlgorithmChacha;
type TEncryptedURISupportedAlgorithm = keyof typeof supportedAlgorithm;

type TEncryptedURIAESWithInitializationVectorParams = TEncryptedURI<{ iv: string }>;
type TEncryptedURIAESWithNumberOnceParams = TEncryptedURI<{ no: string }>;

function getInitializationVector(encryptedUriDecoded: TEncryptedURIAESWithInitializationVectorParams | undefined): Uint8Array {
  return utf8ToBytes(encryptedUriDecoded?.params?.iv || encryptedUriDecoded?.queryString || '');
}

function getNumberOnce(encryptedUriDecoded: TEncryptedURIAESWithNumberOnceParams | undefined): Uint8Array {
  return utf8ToBytes(encryptedUriDecoded?.params?.no || encryptedUriDecoded?.queryString || '');
}


class URIEncryptedAESCBCEncrypter extends URIEncryptedEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const ivString = this.params?.params?.iv || this.params.queryString || '';
    const key = utf8ToBytes(this.params.key);
    const iv = utf8ToBytes(ivString);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/cbc',
      cypher: AESOperationMode
        .cbc(key, iv)
        .encrypt(content)
        .toString(),
      params: {
        iv: ivString
      }
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
    const ivString = this.decoded?.params?.iv || this.decoded.queryString || '';
    const key = utf8ToBytes(this.key);
    const iv = utf8ToBytes(ivString);
    const cypher = utf8ToBytes(this.decoded.cypher || '');

    return AESOperationMode
      .cbc(key, iv)
      .decrypt(cypher)
      .toString();
  }
}

class URIEncryptedAESCBCCTREncrypter extends URIEncryptedEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESWithInitializationVectorParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const ivString = this.params?.params?.iv || this.params.queryString || '';
    const key = utf8ToBytes(this.params.key);
    const iv = utf8ToBytes(ivString);
    const content = utf8ToBytes(this.params.content);

    return {
      algorithm: 'aes/cbc',
      cypher: AESOperationMode
        .ctr(key, iv)
        .encrypt(content)
        .toString(),
      params: {
        iv: ivString
      }
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
    const ivString = this.decoded?.params?.iv || this.decoded.queryString || '';
    const key = utf8ToBytes(this.key);
    const iv = utf8ToBytes(ivString);
    const cypher = utf8ToBytes(this.decoded.cypher || '');

    return AESOperationMode
      .cbc(key, iv)
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
      algorithm: 'aes/cbc',
      cypher: AESOperationMode
        .ecb(key)
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

    return AESOperationMode
      .ecb(key)
      .decrypt(cypher)
      .toString();
  }
}

for (let cipher of [gcm, siv]) {
  const stream = cipher(key, randomBytes(12));
  const ciphertext_ = stream.encrypt(plaintext);
  const plaintext_ = stream.decrypt(ciphertext_);
}
for (const cipher of [ctr, cbc]) {
  const stream = cipher(key, randomBytes(16));
  const ciphertext_ = stream.encrypt(plaintext);
  const plaintext_ = stream.decrypt(ciphertext_);
}
for (const cipher of [ecb]) {
  const stream = cipher(key);
  const ciphertext_ = stream.encrypt(plaintext);
  const plaintext_ = stream.decrypt(ciphertext_);
}

URIEncrypted.setAlgorithm('', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
URIEncrypted.setAlgorithm('aes', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
URIEncrypted.setAlgorithm('aes/cbc', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
URIEncrypted.setAlgorithm('aes/ebc', URIEncryptedAESECBEncrypter, URIEncryptedAESECBDecrypter);
