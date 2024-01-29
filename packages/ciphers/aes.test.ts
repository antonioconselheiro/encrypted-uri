
import { EncryptedURI } from '@encrypted-uri/core';
import './aes';
import './hashes';

describe('aes', () => {
  it('cbc', async () => {
    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/cbc',
      content: originalMessage,
      password
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('ctr', async () => {
    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ctr',
      content: originalMessage,
      password
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('ecb', async () => {
    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/ecb',
      content: originalMessage,
      password
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('gcm', async () => {
    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/gcm',
      content: originalMessage,
      password
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });

  it('siv', async () => {
    const originalMessage = 'mensagem secreta, favor não ler em voz alta';
    const password = 'senha123';

    const encoded = await EncryptedURI.encrypt({
      algorithm: 'aes/siv',
      content: originalMessage,
      password
    });

    const decoded = await EncryptedURI.decrypt(encoded, password);
    expect(decoded).toEqual(originalMessage);
  });
});
