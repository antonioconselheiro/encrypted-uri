import { TEncryptedURIKDFConfig } from '@encrypted-uri/core';
import { pbkdf2 } from '@noble/hashes/pbkdf2';

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
    pbkdf2(sha256, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha256, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha384, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha512, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha512_256, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha3_224, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha3_256, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha3_384, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(sha3_512, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(keccak_224, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(keccak_256, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(keccak_384, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
    pbkdf2(keccak_512, password, salt, { c: cfg.rounds, dkLen: cfg.derivateKeyLength });
  } else {
    throw new Error(`kdf "${cfg.kdf}" not supported`);
  }
}
