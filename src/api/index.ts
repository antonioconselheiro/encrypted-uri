const supportedAlgorithm = {
  aes: 'aes',
  salsa20: 'salsa20',
  chacha: 'chacha',
  xsalsa20: 'xsalsa20',
  xchacha: 'xchacha',
  poly1305: 'poly1305',
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
  pkcs7: 'pkcs#7',
  ansix923: 'ansix923',
  iso10126: 'iso10126',
  iso97971: 'iso97971',
  zeropad: 'zeropad',
  nopad: 'nopad'
};

const supportedAlgorithmList = Object.keys(supportedAlgorithm);
const AESOperationModeList = Object.keys(AESOperationMode);

type TEncryptedURISupportedAlgorithm = keyof typeof supportedAlgorithm;

type TEncryptedURIDefaultParams = {
  algorithm: TEncryptedURISupportedAlgorithm;
  cypher: string;
}

type TEncryptedAESParams = {
  algorithm: 'aes';
  mode: keyof typeof AESOperationMode;
  initializationVector: string;
  padding: keyof typeof AESPadding;
}

type TEncryptedNumberOnceParams = {
  algorithm: 'salsa20' | 'chacha' | 'xsalsa20' | 'xchacha' | 'poly1305' | 'chacha8' | 'chacha12';
  numberOnce: string;
};

type TEncryptedURIResultset = (TEncryptedAESParams | TEncryptedNumberOnceParams) & TEncryptedURIDefaultParams;
  