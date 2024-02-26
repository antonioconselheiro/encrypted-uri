import { TEncryptedURI, TEncryptedURIResultset } from '@encrypted-uri/core';
import { bytesToHex } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

export type TInitializationVectorParams = { iv: string };

export function getInitializationVector(args: TEncryptedURIResultset<TInitializationVectorParams> | TEncryptedURI<TInitializationVectorParams> | undefined): string {
  if (args) {
    const iv = args.params?.iv || 'queryString' in args && args.queryString;
    if (iv) {
      return iv;
    }
  }

  const initializationVectorLength = 16;
  return bytesToHex(randomBytes(initializationVectorLength));
}
