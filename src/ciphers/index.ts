import { URIEncryptedParser } from "@encrypted-uri/parser";

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
  cbc: 'cbc',
  ecb: 'ecb',
  ctr: 'ctr',
  gcm: 'gcm',
  siv: 'siv'
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
     * initializationVector
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

type TEncryptedURIArguments = (TEncryptedAESParams | TEncryptedChachaParams);

class URIEncryptedAESEncrypter implements URIEncryptedEncrypter {
  constructor(
    private params: TEncryptedURIEncryptableDefaultParams & TEncryptedAESParams
  ) { }

  encrypt(): string {
    return '';
  }
}

class URIEncryptedAESDecrypter implements URIEncryptedDecrypter {
  constructor(
    private encoded: string,
    private key: string
  ) { }

  decrypt(): string {
    const parser = new URIEncryptedParser(this.encoded);
    const decoded = parser.decoded;

    return '';
  }
}

class URIEncryptedChachaEncrypter implements URIEncryptedEncrypter {
  constructor(
    private params: TEncryptedURIEncryptableDefaultParams & TEncryptedChachaParams
  ) { }

  encrypt(): string {
    return '';
  }
}

class URIEncryptedChachaDecrypter implements URIEncryptedDecrypter {
  constructor(
    private encoded: string,
    private key: string
  ) { }

  decrypt(): string {
    const parser = new URIEncryptedParser(this.encoded);
    const decoded = parser.decoded;

    return '';
  }
}


static readonly supportedAlgorithm: {
  [algorithm in TEncryptedURISupportedAlgorithm | string]: [
    { new (...args: any[]): URIEncryptedEncrypter },
    { new (...args: any[]): URIEncryptedDecrypter }
  ]
} = {
  aes: [URIEncryptedAESEncrypter, URIEncryptedAESDecrypter],
  salsa20: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  chacha: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  xsalsa20: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  xchacha: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  chacha8: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  chacha12: [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter],
  'xchacha20-poly1305': [URIEncryptedChachaEncrypter, URIEncryptedChachaDecrypter]
}