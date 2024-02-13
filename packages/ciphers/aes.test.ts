
import { EncryptedURI } from '@encrypted-uri/core';
import './aes';
import './hashes';

describe('success flow aes', () => {
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

  it('cbc generated from other implementation with the same algorithm type and params', async () => {
    const decoded = await EncryptedURI.decrypt('encrypted:aes/cbc?iv=1dc8d28370372579a75feac6b5bf5290&c=1000&dklen=8&hasher=md5;U2FsdGVkX18K2mCM3jqJz9SSPC2Rss61NOk4JWeG5IE=', 'teste123');
    expect(decoded).toEqual('teste123');
  });

  it('cbc generated from other implementation with the same algorithm type and params', async () => {
    const decoded = await EncryptedURI.decrypt('encrypted:aes/cbc?iv=9d668dee3bccfd9d3d5fb786aab11894&c=1000&dklen=8&hasher=md5;U2FsdGVkX182g9bXg4UB/MsE9Dlz4lJcGC7WW4WGAVc=', 'exemplo');
    expect(decoded).toEqual('exemplo');
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
