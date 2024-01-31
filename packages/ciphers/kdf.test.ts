import { EncryptedURI, TEncryptedURIKDFConfig } from '@encrypted-uri/core';
import './aes';
import './hashes';

describe('kdf', () => {
  it('[1] kdf with no kdf params and overriding default values in decrypt', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      kdf: 'pbkdf2',
      includeURIParams: false,
      hasher: 'sha256',
      rounds: 100,
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

    const decoded = await EncryptedURI.decrypt(encoded, password, kdf);
    expect(decoded).toEqual(originalMessage);
  });

  it('[2] kdf include all parameters including default', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      kdf: 'pbkdf2',
      includeURIParams: true,
      ignoreDefaults: false,
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
      kdf
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[3] kdf with hasher sha512', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[4] kdf with hasher sha512_256', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[5] kdf with hasher sha384', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[6] kdf with hasher sha3_512', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[7] kdf with hasher sha3_384', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[8] kdf with hasher sha3_256', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[9] kdf with hasher sha3_224', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[10] kdf with hasher keccak_512', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[11] kdf with hasher keccak_384', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[12] kdf with hasher keccak_256', async () => {
    const kdf: TEncryptedURIKDFConfig = {
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

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('[13] kdf with hasher keccak_224', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'keccak_224'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });
});
