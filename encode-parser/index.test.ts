import { expect } from 'chai';
import { URIEncrypted } from '.';

describe('decode uri with default values', () => {
  it('decode uri with default values not include', () => {
    expect(new URIEncrypted('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata').decoded)
      .to.eql({
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
      .to.eql({
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
      .to.eql({
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
      .to.eql({
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
      .to.eql({
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
      .to.eql({
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

describe('encode uri with configs', () => {
  it('encode with default config with default values', () => {
    expect(new URIEncrypted({
      algorithm: 'aes',
      mode: 'cbc',
      cypher: 'en1e3kj3e31jn2algoritmgenerateddata',
      params: {
        iv: '2345678wertyui',
        pad: 'pkcs7'
      }
    }).encoded).to.eql('encrypted:?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes/cbc?2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs7;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes/cbc?iv=2345678wertyui;en1e3kj3e31jn2algoritmgenerateddata')
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
    }).encoded).to.eql('encrypted:aes/cbc?iv=2345678wertyui&pad=pkcs7;en1e3kj3e31jn2algoritmgenerateddata')
  });
});
