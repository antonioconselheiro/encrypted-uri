import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, EncryptedURI, EncryptedURIDecrypter, EncryptedURIEncrypter, EncryptedURIParser } from ".";
import { randomBytes } from '@noble/hashes/utils'

describe('decode uri with default values', () => {
  it('[1] decode uri with default values not include', () => {
    expect(new EncryptedURIParser('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      })
  });

  it('[2] decode uri with some default values not include', () => {
    expect(new EncryptedURIParser('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      })
  });

  it('[3] decode uri with some default values not include', () => {
    expect(new EncryptedURIParser('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes/cbc',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      });
  });

  it('[4] decode uri with default values not include', () => {
    expect(new EncryptedURIParser('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui',
        params: {
          iv: '2345678wertyui'
        }
      });
  });

  it('[5] decode uri with some default values not include', () => {
    expect(new EncryptedURIParser('encrypted:aes?pad=pkcs%237&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'pad=pkcs%237&iv=2345678wertyui',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs#7'
        }
      })
  });

  it('[6] decode uri with some default values not include', () => {
    expect(new EncryptedURIParser('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes/cbc',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui&pad=pkcs%237',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs#7'
        }
      });
  });
});

describe('decode uri with customized values', () => {
  it('[1] decode aes/gcm with customized values', () => {
    expect(new EncryptedURIParser('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes/gcm',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui&pad=ecb',
        params: {
          iv: '2345678wertyui',
          pad: 'ecb'
        }
      });
  });

  it('[2] decode salsa20 with customized values', () => {
    expect(new EncryptedURIParser('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'salsa20',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'no=871232183987132082713',
        params: {
          //  nonce
          no: '871232183987132082713'
        }
      });
  });

  it('[3] decode xchacha with customized values', () => {
    expect(new EncryptedURIParser('encrypted:xchacha?871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'xchacha',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '871232183987132082713'
      });
  });

  it('[4] decode chacha12 with customized values', () => {
    expect(new EncryptedURIParser('encrypted:chacha12?871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'chacha12',
        cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '871232183987132082713'
      });
  });
});

describe('encode uri with configs using default values', () => {
  it('[1] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[2] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes/cbc',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[3] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[4] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes/cbc',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[5] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes/cbc',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs#7'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[6] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui'
      }
    }).encoded).toEqual('encrypted:aes?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[7] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes/cbc',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: 'iv=2345678wertyui'
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[8] encode with default config with default values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes/cbc',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs#7'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata')
  });
});

describe('encode uri with customized values', () => {
  it('[1] encode aes/gcm with customized values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'aes/gcm',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'ecb'
      }
    }).encoded).toEqual('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[2] encode salsa20 with customized values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'salsa20',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[3] encode xchacha with customized values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'xchacha',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[4] encode chacha12 with customized values', () => {
    expect(new EncryptedURIParser({
      algorithm: 'chacha12',
      cipher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });
});

describe('uri matcher', () => {
  it('[1] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[2] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[3] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[4] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[5] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:aes?pad=pkcs%237&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[6] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[7] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[8] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[9] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[10] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[11] match valid encrypted uri', () => {
    expect(EncryptedURIParser.matcher('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
    .toEqual(true);
  });
});

describe('EncryptedURI object', () => {
  class CustomDecrypter extends EncryptedURIDecrypter {

    constructor(
      decoded: TEncryptedURI
    ) {
      super(decoded);
    }
  
    decrypt(): Promise<string> {
      return Promise.resolve(atob(this.decoded.cipher || ''));
    }
  }
  
  class CustomEncrypter extends EncryptedURIEncrypter {
    constructor(
      params: TEncryptedURIEncryptableDefaultParams
    ) {
      super(params);
    }
  
    encrypt(): Promise<TEncryptedURI> {
      return Promise.resolve({
        algorithm: 'custom',
        cipher: btoa(this.params.content)
      });
    }
  }

  const encoded = 'encrypted:custom;YmFzZTY0IG7jbyDpIGNyaXB0b2dyYWZpYQ==';

  it('[1] match valid encrypted uri', () => {
    EncryptedURI.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
    expect(EncryptedURI.matcher(encoded)).toEqual(true);
  });

  it('[2] EncryptedURI must run decrypt for custom algorithm', () => {
    EncryptedURI.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
    EncryptedURI.decrypt(encoded, randomBytes(16)).then(content => {
      expect(content).toEqual('base64 não é criptografia');
    });
  });

  it('[3] EncryptedURI must run encrypt for custom algorithm', () => {
    EncryptedURI.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
    EncryptedURI.encrypt({
      algorithm: 'custom',
      content: 'base64 não é criptografia',
      key: randomBytes(16)
    }).then(result => {
      expect(result).toEqual(encoded);
    })
  });

});
