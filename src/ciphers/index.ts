import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, URIEncryptedDecrypter, URIEncryptedEncrypter } from "@encrypted-uri/core";
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
  'xchacha20-poly1305': 'xchacha20-poly1305'
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


type TEncryptedAESParams = {
  /**
   * @default aes
   */
  algorithm?: 'aes';

  /**
   * @default CBC
   */
  mode?: keyof typeof AESOperationMode;

  params: {
    /**
     * Initialization Vector
     */
    iv: string;

    /**
     * padding system
     * @default pkcs#7
     */
    pad?: keyof typeof AESPadding;
  }
}

type TEncryptedChachaParams = {
  algorithm?: TEncryptedURISupportedChachaAlgorithm;
  numberOnce: string;
};

class URIEncryptedAESCBCEncrypter extends URIEncryptedEncrypter {

  constructor(
    protected override params: TEncryptedURIEncryptableDefaultParams & TEncryptedAESParams
  ) {
    super(params);
  }

  encrypt(): TEncryptedURI {
    return {
      algorithm: 'aes'
    };
  }
}

class URIEncryptedAESCBCDecrypter extends URIEncryptedDecrypter {
  constructor(
    decoded: TEncryptedURI,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {

    return '';
  }
}

class URIEncryptedChachaEncrypter implements URIEncryptedEncrypter {
  constructor(
    protected params: TEncryptedURIEncryptableDefaultParams & TEncryptedChachaParams
  ) { }

  encrypt(): TEncryptedURI {
    return '';
  }
}

class URIEncryptedChachaDecrypter extends URIEncryptedDecrypter {
  constructor(
    decoded: TEncryptedURI,
    private key: string
  ) {
    super(decoded);
  }

  decrypt(): string {
    const parser = new URIEncryptedParser(this.decoded);
    const decoded = parser.decoded;

    return '';
  }
}


const supportedAlgorithm: {
  [algorithm in TEncryptedURISupportedAlgorithm | string]: [
    { new (...args: any[]): URIEncryptedEncrypter },
    { new (...args: any[]): URIEncryptedDecrypter }
  ]
} = {
  aes: [URIEncryptedAESCBCEncrypter, URIEncryptedAESCBCDecrypter],
  salsa20: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  chacha: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  xsalsa20: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  xchacha: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  chacha8: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  chacha12: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  'xchacha20-poly1305': [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter]
}