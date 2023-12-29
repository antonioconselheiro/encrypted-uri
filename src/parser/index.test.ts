import { URIEncrypted } from ".";

describe('decode uri with default values', () => {
  it('[1] decode uri with default values not include', () => {
    expect(new URIEncrypted('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      })
  });

  it('[2] decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      })
  });

  it('[3] decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '2345678wertyui'
      });
  });

  it('[4] decode uri with default values not include', () => {
    expect(new URIEncrypted('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui',
        params: {
          iv: '2345678wertyui'
        }
      });
  });

  it('[5] decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes?pad=pkcs#7&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'pad=pkcs#7&iv=2345678wertyui',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs#7'
        }
      })
  });

  it('[6] decode uri with some default values not include', () => {
    expect(new URIEncrypted('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'aes',
        mode: 'cbc',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: 'iv=2345678wertyui&pad=pkcs#7',
        params: {
          iv: '2345678wertyui',
          pad: 'pkcs#7'
        }
      });
  });
});

describe('decode uri with customized values', () => {
  it('[1] decode aes/gcm with customized values', () => {
    expect(new URIEncrypted('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata').decoded)
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
    expect(new URIEncrypted('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
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
    expect(new URIEncrypted('encrypted:xchacha?871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'xchacha',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '871232183987132082713'
      });
  });

  it('[4] decode chacha12 with customized values', () => {
    expect(new URIEncrypted('encrypted:chacha12?871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .toEqual({
        algorithm: 'chacha12',
        cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
        queryString: '871232183987132082713'
      });
  });
});

describe('encode uri with configs using default values', () => {
  it('[1] encode with default config with default values', () => {
    expect(new URIEncrypted({
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[2] encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui'
      }
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[3] encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[4] encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: '2345678wertyui'
    }).encoded).toEqual('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[5] encode with default config with default values', () => {
    expect(new URIEncrypted({
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
    expect(new URIEncrypted({
      algorithm: 'aes',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui'
      }
    }).encoded).toEqual('encrypted:aes?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[7] encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      queryString: 'iv=2345678wertyui'
    }).encoded).toEqual('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[8] encode with default config with default values', () => {
    expect(new URIEncrypted({
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

  it('[2] encode salsa20 with customized values', () => {
    expect(new URIEncrypted({
      algorithm: 'salsa20',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[3] encode xchacha with customized values', () => {
    expect(new URIEncrypted({
      algorithm: 'xchacha',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        //  nonce
        no: '871232183987132082713'
      }
    }).encoded).toEqual('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata')
  });

  it('[4] encode chacha12 with customized values', () => {
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

describe('uri matcher', () => {
  it('[1] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[2] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[3] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[4] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[5] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:aes?pad=pkcs#7&iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[6] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs%237;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[7] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[8] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:aes/gcm?iv=2345678wertyui&pad=ecb;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[9] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:salsa20?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[10] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:xchacha?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
      .toEqual(true);
  });

  it('[11] match valid encrypted uri', () => {
    expect(URIEncrypted.matcher('encrypted:chacha12?no=871232183987132082713;en1e3kj3e31jn2algoritmgenerateddata'))
    .toEqual(true);
  });
});

