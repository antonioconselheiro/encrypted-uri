import { TEncryptedURIParams, TURIParams } from '@encrypted-uri/core';
import { hexToBytes } from '@noble/ciphers/utils';
import { OpenSSLSerializer } from './openssl-serializer';

export function getSalt<T extends TURIParams>(
  cipher: Uint8Array, params?: TEncryptedURIParams<T>
): Uint8Array {
  const deserialized = OpenSSLSerializer.decode(cipher);
  if (deserialized.salt) {
    return deserialized.salt;
  } else if (params?.s) {
    return hexToBytes(params.s)
  }

  throw new Error('salt not found, can\'t open cipher');
}