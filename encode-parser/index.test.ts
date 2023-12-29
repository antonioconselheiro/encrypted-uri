import { URIEncrypted } from ".";

describe('decode uri with default values', () => {
  it('decode uri with default values not include', () => {
    expect(new URIEncrypted('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs7'
        }
      })
  });

  it('decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs7'
        }
      })
  });

  it('decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs7'
        }
      });
  });

  it('decode uri with default values not include', () => {
    expect(new URIEncrypted('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs7'
        }
      })
  });

  it('decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes?pad=pkcs7&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs7'
        }
      })
  });

  it('decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs7;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs7'
        }
      });
  });
});

describe('encode uri with configs using default values', () => {
  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }).encoded).toEqual('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      includeDefaults: true
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      alwaysIncludeAlgorithm: true
    }).encoded).toEqual('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      alwaysIncludeAlgorithm: true,
      alwaysIncludeMode: true
    }).encoded).toEqual('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      alwaysIncludeAlgorithm: true,
      alwaysIncludeMode: true,
      alwaysIncludePadding: true
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs7;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      alwaysIncludeDefaultArgumentName: true,
      alwaysIncludeAlgorithm: true
    }).encoded).toEqual('encrypted:aes?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      alwaysIncludeAlgorithm: true,
      alwaysIncludeMode: true,
      alwaysIncludeDefaultArgumentName: true
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }, {
      alwaysIncludeAlgorithm: true,
      alwaysIncludeMode: true,
      alwaysIncludePadding: true,
      alwaysIncludeDefaultArgumentName: true
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs7;en1e3kj3e31jn2algoritmgenerateddata')
  });
});

describe('encode uri with customized values', () => {
  it('encode aes/gcm with customized values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'gcm',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'ecb'
      }
    }).encoded).toEqual('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode salsa20 with customized values', () => {
    expect(new URIEncrypted({
      algorithm: 'salsa20',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode xchacha with customized values', () => {
    expect(new URIEncrypted({
      algorithm: 'xchacha',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('encode chacha12 with customized values', () => {
    expect(new URIEncrypted({
      algorithm: 'chacha12',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });
});

describe('decode uri with customized values', () => {
  it('decode aes/gcm with customized values', () => {
    expect(new URIEncrypted('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual(new URIEncrypted({
        algorithm: 'aes',
        mode: 'gcm',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          iv: '2345678wertyui',
          pad: 'ecb'
        }
      }));
  });

  it('decode salsa20 with customized values', () => {
    expect(new URIEncrypted('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual(new URIEncrypted({
        algorithm: 'salsa20',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          //  nonce
          no: '871232183987132082713'
        }
      }));
  });

  it('decode xchacha with customized values', () => {
    expect(new URIEncrypted('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual(new URIEncrypted({
        algorithm: 'xchacha',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          //  nonce
          no: '871232183987132082713'
        }
      }));
  });

  it('decode chacha12 with customized values', () => {
    expect(new URIEncrypted('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual(new URIEncrypted({
        algorithm: 'chacha12',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        params: {
          //  nonce
          no: '871232183987132082713'
        }
      }));
  });
});
