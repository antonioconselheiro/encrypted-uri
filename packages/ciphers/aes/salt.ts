import { TEncryptedURIParams } from '@encrypted-uri/core';
import { hexToBytes } from '@noble/ciphers/utils';

export function getSalt(deserialized: {
  salt?: Uint8Array
}, params?: TEncryptedURIParams): Uint8Array {
  if (deserialized.salt) {
    return deserialized.salt;
  } else if (params?.s) {
    return hexToBytes(params.s)
  }

  throw new Error('salt not found, can\'t open cipher');
}