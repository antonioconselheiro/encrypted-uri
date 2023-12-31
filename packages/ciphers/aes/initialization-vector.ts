import { TEncryptedURI } from '@encrypted-uri/core';
import { bytesToHex } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

export type TEncryptedURIAESWithInitializationVectorParams = TEncryptedURI<{ iv: string }>;

export function getInitializationVector(args: TEncryptedURIAESWithInitializationVectorParams | undefined): string {
  return args?.params?.iv || args?.queryString || bytesToHex(randomBytes(16));
}
