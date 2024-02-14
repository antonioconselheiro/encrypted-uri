import { EncryptedURI, TEncryptedURIKDFConfig } from '@encrypted-uri/core';
import './aes';
import './hashes';

describe('kdf success flow', () => {

  it('[2] kdf include all parameters including default', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      kdf: 'pbkdf2',
      ignoreDefaults: false,
      hasher: 'sha256',
      rounds: 10,
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

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[3] kdf with hasher sha512', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha512' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/gcm',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[4] kdf with hasher sha512_256', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha512_256' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/gcm',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[5] kdf with hasher sha384', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha384' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/siv',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[6] kdf with hasher sha3_512', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha3_512' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ctr',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[7] kdf with hasher sha3_384', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha3_384' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ctr',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[8] kdf with hasher sha3_256', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha3_256' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ecb',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[9] kdf with hasher sha3_224', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'sha3_224' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ecb',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[10] kdf with hasher keccak_512', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'keccak_512' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[11] kdf with hasher keccak_384', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'keccak_384' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[12] kdf with hasher keccak_256', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'keccak_256' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });

  it('[13] kdf with hasher keccak_224', async () => {
    const kdf: TEncryptedURIKDFConfig = {
      hasher: 'keccak_224' as any as 'sha256'
    };

    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password,
      kdf
    });

    const decrypted = await EncryptedURI.decrypt(encoded, password);
    expect(decrypted).toEqual(originalMessage);
  });
});
