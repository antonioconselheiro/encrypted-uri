import { TEncryptedURIKDFConfig } from '@encrypted-uri/core';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';

const defaultConfigs: Required<TEncryptedURIKDFConfig> = {
  kdf: 'pbkdf2',
  hasher: 'sha256',
  ignoreDefaults: true,
  includeURIParams: true,
  derivateKeyLength: 32,
  rounds: 32
};

export function kdf(password: string, salt: Uint8Array, config?: TEncryptedURIKDFConfig): Uint8Array {
  const cfg: Required<TEncryptedURIKDFConfig> = { ...defaultConfigs, ...config };

  if (cfg.kdf === 'pbkdf2') {
    return pbkdf2(sha256, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
  } else {
    throw new Error(`kdf "${cfg.kdf}" not supported`);
  }
}
