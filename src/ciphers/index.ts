import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, URIEncrypted, URIEncryptedDecrypter, URIEncryptedEncrypter } from "@encrypted-uri/core";
import { cbc, ecb, ctr, gcm, siv } from '@noble/ciphers/aes';

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

function toUint8Array(content: string): Uint8Array {
  return new Uint8Array(
    new TextEncoder()
      .encode(content)
  );
}

type TEncryptedURIAESCBCParams = TEncryptedURI<{ iv: string }>;

class URIEncryptedAESCBCEncrypter extends URIEncryptedEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIAESCBCParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    const ivString = this.params?.params?.iv || this.params.queryString || '';
    const key = toUint8Array(this.params.key);
    const iv = toUint8Array(ivString);
    const content = toUint8Array(this.params.content);

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

class URIEncryptedAESCBCDecrypter extends URIEncryptedDecrypter<TEncryptedURIAESCBCParams> {
  constructor(
    decoded: TEncryptedURIAESCBCParams,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const ivString = this.decoded?.params?.iv || this.decoded.queryString || '';
    const key = toUint8Array(this.key);
    const iv = toUint8Array(ivString);
    const cypher = toUint8Array(this.decoded.cypher || '');

    return AESOperationMode
      .cbc(key, iv)
      .decrypt(cypher)
      .toString();
  }
}

URIEncrypted.setAlgorithm('', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
URIEncrypted.setAlgorithm('aes', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);
URIEncrypted.setAlgorithm('aes/cbc', URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter);