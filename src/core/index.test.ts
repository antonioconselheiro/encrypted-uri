import { TEncryptedURI, TEncryptedURIEncryptableDefaultParams, URIEncrypted, URIEncryptedDecrypter, URIEncryptedEncrypter, URIEncryptedParser } from ".";

describe('decode uri with default values', () => {
  it('[1] decode uri with default values not include', () => {
    expect(new URIEncryptedParser('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      })
  });

  it('[2] decode uri with some default values not include', () => {
    expect(new URIEncryptedParser('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      })
  });

  it('[3] decode uri with some default values not include', () => {
    expect(new URIEncryptedParser('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      });
  });

  it('[4] decode uri with default values not include', () => {
    expect(new URIEncryptedParser('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui',
        params: {
          iv: '2345678wertyui'
        }
      });
  });

  it('[5] decode uri with some default values not include', () => {
    expect(new URIEncryptedParser('encrypted:aes?pad=pkcs%237&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'pad=pkcs%237&iv=2345678wertyui',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs#7'
        }
      })
  });

  it('[6] decode uri with some default values not include', () => {
    expect(new URIEncryptedParser('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
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
    expect(new URIEncryptedParser('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'gcm',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui&pad=ecb',
        params: {
          iv: '2345678wertyui',
          pad: 'ecb'
        }
      });
  });

  it('[2] decode salsa20 with customized values', () => {
    expect(new URIEncryptedParser('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'salsa20',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'no=871232183987132082713',
        params: {
          //  nonce
          no: '871232183987132082713'
        }
      });
  });

  it('[3] decode xchacha with customized values', () => {
    expect(new URIEncryptedParser('encrypted:xchacha?871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'xchacha',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '871232183987132082713'
      });
  });

  it('[4] decode chacha12 with customized values', () => {
    expect(new URIEncryptedParser('encrypted:chacha12?871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'chacha12',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '871232183987132082713'
      });
  });
});

describe('encode uri with configs using default values', () => {
  it('[1] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[2] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[3] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[4] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[5] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs#7'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[6] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui'
      }
    }).encoded).toEqual('encrypted:aes?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[7] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: 'iv=2345678wertyui'
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[8] encode with default config with default values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs#7'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata')
  });
});

describe('encode uri with customized values', () => {
  it('[1] encode aes/gcm with customized values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'aes',
      mode: 'gcm',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'ecb'
      }
    }).encoded).toEqual('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[2] encode salsa20 with customized values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'salsa20',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[3] encode xchacha with customized values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'xchacha',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[4] encode chacha12 with customized values', () => {
    expect(new URIEncryptedParser({
      algorithm: 'chacha12',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });
});

describe('uri matcher', () => {
  it('[1] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[2] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[3] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[4] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[5] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:aes?pad=pkcs%237&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[6] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[7] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[8] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[9] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[10] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[11] match valid encrypted uri', () => {
    expect(URIEncryptedParser.matcher('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
    .toEqual(true);
  });
});

describe('URIEncrypted object', () => {
  class CustomDecrypter extends URIEncryptedDecrypter {

    constructor(
      decoded: TEncryptedURI
    ) {
      super(decoded);
    }
  
    decrypt(): string {
      console.info('[this.decoded]: ', this.decoded);
      console.info('[this.decoded.cypher]: ', this.decoded.cypher);

      return atob(this.decoded.cypher || '');
    }
  }
  
  class CustomEncrypter extends URIEncryptedEncrypter {
    constructor(
      params: TEncryptedURIEncryptableDefaultParams
    ) {
      super(params);
    }
  
    encrypt(): TEncryptedURI {
      return {
        algorithm: 'custom',
        cypher: btoa(this.params.content)
      };
    }
  }

  const encoded = 'encrypted:custom;YmFzZTY0IG7jbyDpIGNyaXB0b2dyYWZpYQ==';

  it('[1] match valid encrypted uri', () => {
    URIEncrypted.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
    expect(URIEncrypted.matcher(encoded)).toEqual(true);
  });

  it('[2] URIEncrypted must run decrypt for custom algorithm', () => {
    URIEncrypted.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
    expect(URIEncrypted.decrypt(encoded, 'key here')).toEqual('base64 não é criptografia');
  });

  it('[3] URIEncrypted must run encrypt for custom algorithm', () => {
    URIEncrypted.setAlgorithm('custom', CustomEncrypter, CustomDecrypter);
    expect(URIEncrypted.encrypt({
      algorithm: 'custom',
      content: 'base64 não é criptografia',
      key: 'key here'
    })).toEqual(encoded);
  });

});
