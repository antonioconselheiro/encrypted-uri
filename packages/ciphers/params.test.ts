import { EncryptedURI, EncryptedURIParser, TEncryptedDefaultsConfig, TEncryptedURIKDFParams } from '@encrypted-uri/core';
import './aes';
import './hashes';

describe('hashing customization', () => {
  it('[1] kdf with hasher sha512', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha512'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/gcm',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/gcm');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha512');
  });

  it('[2] kdf with hasher sha512_256', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha512_256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/gcm',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/gcm');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha512_256');
  });

  it('[3] kdf with hasher sha384', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha384'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/siv',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/siv');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha384');
  });

  it('[4] kdf with hasher sha3_512', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha3_512'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ctr',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/ctr');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha3_512');
  });

  it('[5] kdf with hasher sha3_384', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha3_384'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ctr',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/ctr');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha3_384');
  });

  it('[6] kdf with hasher sha3_256', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha3_256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ecb',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/ecb');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha3_256');
  });

  it('[7] kdf with hasher sha3_224', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'sha3_224'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ecb',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/ecb');
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('sha3_224');
  });

  it('[8] kdf with hasher keccak_512', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'keccak_512'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('keccak_512');
  });

  it('[9] kdf with hasher keccak_384', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'keccak_384'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('keccak_384');
  });

  it('[10] kdf with hasher keccak_256', async () => {
    const kdf: TEncryptedURIKDFParams = {
      hasher: 'keccak_256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual('keccak_256');
  });
});

describe('checking if params are correctly encoded', () => {
  it('[1] overriding default values in decrypt', async () => {
    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 250_000,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ctr',
      content: originalMessage,
      password,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual('aes/ctr');
    expect(parser.decoded.params?.c).toEqual('250000');
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual(undefined);
  });

  it('[2] kdf include all parameters including default', async () => {
    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 100,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config: {
        ignoreDefaults: false
      },
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual('aes/cbc');
    expect(parser.decoded.params?.kdf).toEqual('pbkdf2');
    expect(parser.decoded.params?.c).toEqual('100');
    expect(parser.decoded.params?.dklen).toEqual('32');
    expect(parser.decoded.params?.h).toEqual('sha256');
  });

  it('[3] kdf with algorithm not set', async () => {
    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      content: originalMessage,
      password
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual(undefined);
  });
});

describe('configs of defaults', () => {
  it('[1] ignoreDefaults as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaults: true
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual(undefined);
  });

  it('[2] ignoreDefaults as false', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaults: false
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual('aes/cbc');
    expect(parser.decoded.params?.kdf).toEqual('pbkdf2');
    expect(parser.decoded.params?.c).toEqual('32');
    expect(parser.decoded.params?.dklen).toEqual('32');
    expect(parser.decoded.params?.h).toEqual('sha256');
  });

  it('[3] ignoreDefaultAlgorithm as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaultAlgorithm: true,
      ignoreDefaultValues: false,
      ignoreMandatoryParamName: false
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.kdf).toEqual('pbkdf2');
    expect(parser.decoded.params?.c).toEqual('32');
    expect(parser.decoded.params?.dklen).toEqual('32');
    expect(parser.decoded.params?.h).toEqual('sha256');
  });

  it('[4] ignoreDefaultValues as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaultAlgorithm: false,
      ignoreDefaultValues: true,
      ignoreMandatoryParamName: false
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual('aes/cbc');
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual(undefined);
  });

  it('[5] ignoreMandatoryParamName as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaultAlgorithm: false,
      ignoreDefaultValues: false,
      ignoreMandatoryParamName: true
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual('aes/cbc');
    expect(parser.decoded.params?.kdf).toEqual('pbkdf2');
    expect(parser.decoded.params?.c).toEqual('32');
    expect(parser.decoded.params?.dklen).toEqual('32');
    expect(parser.decoded.params?.h).toEqual('sha256');
  });

  it('[6] ignoreDefaultAlgorithm and ignoreMandatoryParamName as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaultAlgorithm: true,
      ignoreDefaultValues: false,
      ignoreMandatoryParamName: true
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.kdf).toEqual('pbkdf2');
    expect(parser.decoded.params?.c).toEqual('32');
    expect(parser.decoded.params?.dklen).toEqual('32');
    expect(parser.decoded.params?.h).toEqual('sha256');
  });

  it('[7] ignoreDefaultAlgorithm and ignoreDefaultValues as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaultAlgorithm: true,
      ignoreDefaultValues: true,
      ignoreMandatoryParamName: false
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual(undefined);
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual(undefined);
  });

  it('[8] ignoreDefaultValues and ignoreMandatoryParamName as true', async () => {
    const config: TEncryptedDefaultsConfig = {
      ignoreDefaultAlgorithm: false,
      ignoreDefaultValues: true,
      ignoreMandatoryParamName: true
    };

    const kdf: TEncryptedURIKDFParams = {
      kdf: 'pbkdf2',
      hasher: 'sha256',
      rounds: 32,
      derivateKeyLength: 32
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      config,
      kdf
    });

    const parser = new EncryptedURIParser(encoded);
    expect(parser.decoded.algorithm).toEqual('aes/cbc');
    expect(parser.decoded.params?.kdf).toEqual(undefined);
    expect(parser.decoded.params?.c).toEqual(undefined);
    expect(parser.decoded.params?.dklen).toEqual(undefined);
    expect(parser.decoded.params?.h).toEqual(undefined);
  });
});