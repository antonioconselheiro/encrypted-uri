import { EncryptedURI, EncryptedURIDecrypter, EncryptedURIEncrypter, TEncryptedURI, TEncryptedURIEncryptableDefaultParams } from "@encrypted-uri/core";
import { ecb, siv } from '@noble/ciphers/aes';
import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import { cbc, ctr, gcm } from '@noble/ciphers/webcrypto/aes';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';





export function supportAES(): void {
  EncryptedURI.setAlgorithm('', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm('aes', EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
}
