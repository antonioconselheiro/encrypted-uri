import { TEncryptedURI, TEncryptedURIResultset } from '@encrypted-uri/core';
import { bytesToHex } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto/utils';

export type TNumberOnceParams = { no: string };

export function getNumberOnce(args: TEncryptedURIResultset<TNumberOnceParams> | TEncryptedURI<TNumberOnceParams> | undefined): string {
  if (args) {
    const no = args.params?.no || 'queryString' in args && args.queryString;
    if (no) {
      return no;
    }
  }

  const numberOnceLength = 12;
  return bytesToHex(randomBytes(numberOnceLength));
}
