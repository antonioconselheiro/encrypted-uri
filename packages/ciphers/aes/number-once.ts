import { TEncryptedURI } from '@encrypted-uri/core';
import { bytesToHex } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

export type TEncryptedURIAESWithNumberOnceParams = TEncryptedURI<{ no: string }>;

export function getNumberOnce(args: TEncryptedURIAESWithNumberOnceParams | undefined): string {
  return args?.params?.no || args?.queryString || bytesToHex(randomBytes(12));
}
