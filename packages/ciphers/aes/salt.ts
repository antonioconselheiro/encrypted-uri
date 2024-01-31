import { TEncryptedURIParams, TURIParams } from '@encrypted-uri/core';
import { hexToBytes } from '@noble/ciphers/utils';
import { OpenSSLSerializer } from './openssl-serializer';

export function getSalt<T extends TURIParams>(
  cipher: Uint8Array, params?: TEncryptedURIParams<T>
): { salt: Uint8Array, cipher: Uint8Array } {
  const deserialized = OpenSSLSerializer.decode(cipher);
  if (deserialized.salt) {
    return { salt: deserialized.salt, cipher: deserialized.cipher };
  } else if (params?.s) {
    return { salt: hexToBytes(params.s), cipher };
  }

  throw new Error('salt not found, can\'t open cipher');
}