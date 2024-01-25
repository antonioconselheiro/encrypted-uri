import { EncryptedURI, TEncryptedURI, TEncryptedURIKDFConfig, TURIParams } from '@encrypted-uri/core';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { HashSupport } from '../hashes/hash-support';

export function kdf<T extends TURIParams>(
  password: string,
  salt: Uint8Array,
  config?: TEncryptedURIKDFConfig | TEncryptedURI<T>
): Uint8Array {
  const cfg = EncryptedURI.getKDFConfig(config);

  if (cfg.kdf === 'pbkdf2') {
    return pbkdf2(HashSupport.get(cfg.hasher), password, salt, {
      c: cfg.rounds,
      dkLen: cfg.derivateKeyLength
    });
  } else {
    throw new Error(`kdf "${cfg.kdf}" not supported`);
  }
}
