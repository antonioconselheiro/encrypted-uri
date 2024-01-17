import { TEncryptedURI, TEncryptedURIKDFConfig, TEncryptedURIParams, TURIParams } from '@encrypted-uri/core';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { HashSupport } from 'hashes/hash-support';

const defaultConfigs: Required<TEncryptedURIKDFConfig> = {
  kdf: 'pbkdf2',
  hasher: 'sha256',
  ignoreDefaults: true,
  includeURIParams: true,
  derivateKeyLength: 32,
  rounds: 32
};

export function kdf<T extends TURIParams>(
  password: string,
  salt: Uint8Array,
  config?: TEncryptedURIKDFConfig | TEncryptedURI<T>
): Uint8Array {
  const cfg = getConfig(config);

  if (cfg.kdf === 'pbkdf2') {
    return pbkdf2(HashSupport.get(cfg.hasher), password, salt, {
      c: cfg.rounds,
      dkLen: cfg.derivateKeyLength
    });
  } else {
    throw new Error(`kdf "${cfg.kdf}" not supported`);
  }
}

function getConfig<T extends TURIParams>(
  configOverload?: TEncryptedURIKDFConfig | TEncryptedURI<T>
): Required<TEncryptedURIKDFConfig> {
  let config: TEncryptedURIKDFConfig = defaultConfigs;
  if (configOverload && 'params' in configOverload) {
    config = castParamsToConfig(configOverload.params);
  }

  const configWithDefaults: Required<TEncryptedURIKDFConfig> = {
    ...defaultConfigs,
    ...config
  };

  return configWithDefaults;
}

function castParamsToConfig<T extends TURIParams>(
  params?: TEncryptedURIParams<T>
): TEncryptedURIKDFConfig {
  const config: TEncryptedURIKDFConfig = {};

  if (!params) {
    return config;
  }

  if (typeof params.kdf === 'string') {
    config.kdf = params.kdf as 'pbkdf2';
  }

  if (typeof params.h === 'string') {
    config.hasher = params.h;
  }

  if (typeof params.dklen === 'string') {
    const derivateKeyLength = Number(params.dklen);
    if (Number.isSafeInteger(derivateKeyLength)) {
      config.derivateKeyLength = derivateKeyLength;
    }
  }

  if (typeof params.c === 'string') {
    const rounds = Number(params.c);
    if (Number.isSafeInteger(rounds)) {
      config.rounds = rounds;
    }
  }

  return config;
}