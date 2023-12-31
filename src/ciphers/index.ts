import { URIEncryptedParser } from "@encrypted-uri/parser";

const supportedAlgorithm = {
  aes: 'aes',
  salsa20: 'salsa20',
  chacha: 'chacha',
  xsalsa20: 'xsalsa20',
  xchacha: 'xchacha',
  chacha8: 'chacha8',
  chacha12: 'chacha12'
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

type TEncryptedURISupportedAlgorithm = keyof typeof supportedAlgorithm;

type TEncryptedURIDefaultParams = {
  algorithm: TEncryptedURISupportedAlgorithm;
}

type TEncryptedURIEncryptedDefaultParams = {
  cypher: string;
} & TEncryptedURIDefaultParams;

type TEncryptedURIEncryptableDefaultParams = {
  content: string;
  key: string;
} & TEncryptedURIDefaultParams;

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
  algorithm: 'salsa20' | 'chacha' | 'xsalsa20' | 'xchacha' | 'chacha8' | 'chacha12';
  numberOnce: string;
};

type TEncryptedURIArguments = (TEncryptedAESParams | TEncryptedChachaParams);

export class URIEncrypted {
  static matcher(uri: string): boolean {
    return URIEncryptedParser.matcher(uri);
  }

  static encode(params: TEncryptedURIEncryptedDefaultParams & TEncryptedURIArguments) {
    return new URIEncryptedParser(params)
  }

  static encrypt(params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIArguments) {
    return new URIEncryptedEncrypter(params).encrypt();
  }

  static decrypt(encoded: string, key: string): string {
    return new URIEncryptedDecrypter(encoded, key).decrypt();
  }
}

class URIEncryptedEncrypter {
  constructor(
    private params: TEncryptedURIEncryptableDefaultParams & TEncryptedURIArguments
  ) { }

  encrypt() {

  }
}

class URIEncryptedDecrypter {
  constructor(
    private encoded: string,
    private key: string
  ) {}

  decrypt(): string {
    const parser = new URIEncryptedParser(this.encoded);
    const decoded = parser.decoded;
  }
}
