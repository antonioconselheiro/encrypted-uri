
const supportedAlgorithm = {
  aes: 'aes',
  salsa20: 'salsa20',
  chacha: 'chacha',
  xsalsa20: 'xsalsa20',
  xchacha: 'xchacha',
  poly1305: 'poly1305',
  chacha8: 'chacha8',
  chacha12: 'chacha12'
};

const AESOperationMode = {
  cbc: 'cbc',
  ecb: 'ecb',
  ctr: 'ctr',
  gcm: 'gcm',
  siv: 'siv'
};

const AESPadding = {
  pkcs7: 'pkcs7',
  ansix923: 'ansix923',
  iso10126: 'iso10126',
  iso97971: 'iso97971',
  zeropad: 'zeropad',
  nopad: 'nopad'
};

const supportedAlgorithmList = Object.keys(supportedAlgorithm);
const AESOperationModeList = Object.keys(AESOperationMode);

type TEncryptedURISupportedAlgorithm = keyof typeof supportedAlgorithm;

type TEncryptedURIDefaultParams = {
  algorithm: TEncryptedURISupportedAlgorithm;
  cypher: string;
}

type TEncryptedAESParams = {
  algorithm: 'aes';
  mode: keyof typeof AESOperationMode;
  initializationVector: string;
  padding: keyof typeof AESPadding;
}

type TEncryptedNumberOnceParams = {
  algorithm: 'salsa20' | 'chacha' | 'xsalsa20' | 'xchacha' | 'poly1305' | 'chacha8' | 'chacha12';
  numberOnce: string;
};

type TEncryptedURIResultset = (TEncryptedAESParams | TEncryptedNumberOnceParams) & TEncryptedURIDefaultParams;

/**
 * When the uri is still being interpreted
 * and has not yet gone through validation
 */
type TEncryptedUnkown = {
  algorithm?: string;
  mode?: string;
  initializationVector?: string;
  padding?: string;
  numberOnce?: string;
}

type TEncryptedURIConfig = {
  includeDefaults: true;
} | ({
  /**
   * The default algorithm is not needed to be set, but
   * you can force setting alwaysIncludeAlgorithm with true,
   * false is the default value.
   * 
   * If false, the default algorithm (AES) will be not included
   * in the final encode.
   * 
   * If true the algorithm information will be always include.
   * 
   * @default false
   */
  alwaysIncludeAlgorithm?: true;

  /**
   * The default padding argument is not needed to be set, but
   * you can force by setting alwaysIncludePadding with true,
   * false is the default value.
   * 
   * If false, the default padding argument (pkcs7) will be not
   * included as argument in the final encode.
   * 
   * If true the argument will be always include.
   */
  alwaysIncludePadding?: true;

  /**
   * If there is no argument but the only mandatory argument
   * (initialization vector and number once), the name of
   * argument and the attribution symbol are not included, but
   * you can force by setting alwaysIncludeDefaultArgumentName
   * with true, false is the default value.
   * 
   * If false, the name of 'iv' argument and 'no' argument will
   * be not included in the encode when it is the only argument.
   * 
   * If true the argument namewill be always include.
   */
  alwaysIncludeDefaultArgumentName?: true;
} & {
  alwaysIncludeAlgorithm: true;

  /**
   * The default algorithm and default operation mode (aes/cbc)
   * don't need to be included, but you can force include it by
   * setting alwaysIncludeAlgorithm with true and alwaysIncludeMode
   * with true too, false is the default value for both config and
   * you can't set alwaysIncludeMode without alwaysIncludeAlgorithm.
   * 
   * If false, the default algorithm and mode (AES-CBC) will be not
   * included in the final encode.
   * 
   * If true the algorithm and mode will be always include in the
   * encode.
   * 
   * @default false
   */
  alwaysIncludeMode?: true;
});

class URIEncrypted {

  static readonly INCLUDE_DEFAULTS = true;
  
  static readonly DEFAULT_ALGORITHM = 'aes';
  static readonly DEFAULT_AES_MODE = 'cbc';
  static readonly DEFAULT_AES_PADDING = 'pkcs7';

  readonly encoded: string;
  readonly decoded: TEncryptedURIResultset;

  constructor(content: TEncryptedURIResultset, config?: TEncryptedURIConfig);
  constructor(content: string);
  constructor(
    content: string | TEncryptedURIResultset,
    config?: TEncryptedURIConfig
  ) {
    if (typeof content === 'string') {
      const decoder = new URIEncryptedDecode();
      this.decoded = decoder.decode(this.encoded = content);
      this.encoded = content;
    } else {
      const encoder = new URIEncryptedEncode();
      this.decoded = content;
      this.encoded = encoder.encode(content, config);
    }
  }
}

class URIEncryptedDecode {

  private readonly ENCRYPTED_URI_IDENTIFIER = /^encrypted:/;
  private readonly QUERY_STRING_IDENTIFIER = /^?.*;+/;

  decode(content: string): TEncryptedURIResultset {
    const resultset: TEncryptedUnkown = {};
    const iterable = new IterableString(content);

    this.checkURI(iterable);
    this.identifySupportedAlgorithm(iterable, resultset);
    this.identifySupportedOperationMode(iterable, resultset);
    this.readQueryString(iterable, resultset);

    if (this.validateDecoded(resultset)) {
      return resultset;
    } else {
      throw new InvalidURIEncrypted();
    }
  }

  private checkURI(iterable: IterableString): void {
    const is = iterable.addCursor(this.ENCRYPTED_URI_IDENTIFIER);
    if (!is) {
      throw new InvalidURIEncrypted('missing \'encrypted\' keyword');
    }
  }

  private identifySupportedAlgorithm(iterable: IterableString, resultset: TEncryptedUnkown): void {
    const identifySupportedAlgorithm = this.getSupportedAlgorithmMatcher();
    const isSupported = iterable.addCursor(identifySupportedAlgorithm);
    if (isSupported) {
      resultset.algorithm = isSupported;
    } else {
      throw new AlgorithmNotSuported('algorithm not supported');
    }
  }

  private identifySupportedOperationMode(iterable: IterableString, resultset: TEncryptedUnkown): void {
    const identifyOperationMode = this.getIdentifyOperationModeMatcher();
    const hasOperationMode = iterable.addCursor(identifyOperationMode);
    if (hasOperationMode) {
      resultset.mode = this.removeNotAlphaNumerical(hasOperationMode);
    }
  }

  private readQueryString(iterable: IterableString, resultset: TEncryptedUnkown): void {
    const isQueryStringFormat = /^\?([^=]+=[^=]+)(&([^=]+=[^=]+))*[;]$/;
    const queryString = iterable.addCursor(this.QUERY_STRING_IDENTIFIER);
    const cleanQueryString = queryString.replace(/;$/, '')
    if (isQueryStringFormat.test(queryString)) {
      const decodedQueryParams = new URL(`encrypted://_${cleanQueryString}`);
      const params = Array
        .from(decodedQueryParams.searchParams.entries())
        .map(([key, value]) => ({ [key]: value }));

      if ('iv' in params) {
        resultset.initializationVector = String(params.iv);
      }

      if ('pad' in params) {
        resultset.padding = String(params.pad);
      }

      if ('no' in params) {
        resultset.numberOnce = String(params.no);
      }
    } else {
      if (resultset.algorithm === 'aes') {
        resultset.initializationVector = cleanQueryString;
      } else {
        resultset.numberOnce = cleanQueryString;
      }
    }
  }

  private validateDecoded(resultset: TEncryptedUnkown): resultset is TEncryptedURIResultset {
    return true;
  }

  private removeNotAlphaNumerical(content: string): string {
    return content.replace(/[^a-z\d]/g, '');
  }

  private getSupportedAlgorithmMatcher(): RegExp {
    const supported = supportedAlgorithmList.join('|');
    return new RegExp(`^(${supported})`);
  }

  private getIdentifyOperationModeMatcher(): RegExp {
    const operationMode = AESOperationModeList.join('|');
    return new RegExp(`^(\/(${operationMode}))?`);
  }
}

class URIEncryptedEncode {
  encode(content: TEncryptedURIResultset, config?: TEncryptedURIConfig): string {
    const algorithm = this.encodeAlgorithmAndMode(content, config);
    const parameters = this.encodeParameters(content, config);

    return `encrypted:${algorithm}?${parameters};${content.cypher}`;
  }

  private encodeParameters(
    content: TEncryptedURIResultset,
    config?: TEncryptedURIConfig
  ): string {
    const {
      alwaysIncludePadding,
      alwaysIncludeDefaultArgumentName
    } = this.normalizeConfig(config);

    const params = new URLSearchParams();
    if ('initializationVector' in content) {
      const isDefaultPadding = content.padding === URIEncrypted.DEFAULT_AES_PADDING;
      const ignoreDefaultPadding = !alwaysIncludePadding;

      params.append('iv', content.initializationVector);
      if (!(ignoreDefaultPadding && isDefaultPadding)) {
        params.append('pad', content.padding);
      } else if (!alwaysIncludeDefaultArgumentName) {
        //  iv is only argument and is configured to not show argument name
        const qs = params.toString();
        return qs.replace(/iv=/, '');
      }

    } else if ('numberOnce' in content) {
      params.append('no', content.numberOnce);
    }

    return params.toString();
  }

  private encodeAlgorithmAndMode(
    content: TEncryptedURIResultset,
    config?: TEncryptedURIConfig
  ) {
    const {
      alwaysIncludeAlgorithm,
      alwaysIncludeMode
    } = this.normalizeConfig(config);

    let algorithm: string = content.algorithm;
    if (content.algorithm === 'aes') {
      if (alwaysIncludeAlgorithm) {
        const isDefaultMode = content.mode === URIEncrypted.DEFAULT_AES_MODE;
        const dontIncludeDefault = !alwaysIncludeMode;
  
        if (!(dontIncludeDefault && isDefaultMode)) {
          algorithm = `${algorithm}/${content.mode}`;
        }
      } else {
        algorithm = '';
      }
    }

    return algorithm;
  }

  private normalizeConfig(config?: TEncryptedURIConfig): {
    alwaysIncludeAlgorithm: boolean;
    alwaysIncludePadding: boolean;
    alwaysIncludeMode: boolean;
    alwaysIncludeDefaultArgumentName: boolean;
  } {
    const includeDefaults = config &&
      'includeDefaults' in config &&
      config.includeDefaults ||
      false;

    const alwaysIncludeAlgorithm = includeDefaults ||
      config &&
      'alwaysIncludeAlgorithm' in config &&
      config.alwaysIncludeAlgorithm
      || false;

    const alwaysIncludePadding = includeDefaults ||
      config &&
      'alwaysIncludePadding' in config &&
      config.alwaysIncludePadding
      || false;

      const alwaysIncludeMode = includeDefaults ||
      config &&
      'alwaysIncludeMode' in config &&
      config.alwaysIncludeMode
      || false;

    const alwaysIncludeDefaultArgumentName = includeDefaults ||
      config &&
      'alwaysIncludeDefaultArgumentName' in config &&
      config.alwaysIncludeDefaultArgumentName
      || false;

    return {
      alwaysIncludeAlgorithm,
      alwaysIncludePadding,
      alwaysIncludeMode,
      alwaysIncludeDefaultArgumentName
    }
  }
}

export class IterableString {

  private cursor = 0;
  private readonly DEBUG_CHARS_PREVIEW = 100;

  constructor(
    private str: string
  ) { }

  get debugInfo(): string {
    return String(this).substring(0, this.DEBUG_CHARS_PREVIEW);
  }

  get currenPosition(): number {
    return this.cursor;
  }

  /**
   * Return the string in it current cursor position
   */
  toString(): string {
    return this.str.substring(this.cursor);
  }

  valueOf(): string {
    return this.str.substring(this.cursor);
  }

  /**
   * Return the original string
   */
  getOriginalString(): string {
    return this.str;
  }

  /**
   * Move the cursor and return the result
   */
  addCursor(param?: number | string | RegExp, autoTrimResult = true): string {
    let result = '';
    if (typeof param === 'number') {
      result = this.addCursorNumeric(param);
    } else if (typeof param === 'string') {
      result = this.addCursorRegExp(new RegExp(param));
    } else if (param instanceof RegExp) {
      result = this.addCursorRegExp(param);
    } else {
      result = this.addCursorNumeric();
    }

    if (autoTrimResult) {
      return result.trim();
    } else {
      return result;
    }
  }

  /**
   * Return result without move cursor
   */
  spy(param?: number | string | RegExp, autoTrimResult = true): string {
    let result = '';
    if (typeof param === 'number') {
      result = this.spyNumeric(param);
    } else if (typeof param === 'string') {
      result = this.spyRegExp(new RegExp(param));
    } else if (param instanceof RegExp) {
      result = this.spyRegExp(param);
    } else {
      result = this.spyNumeric();
    }

    if (autoTrimResult) {
      return result.trim();
    } else {
      return result;
    }
  }

  private spyNumeric(howMuchMore = 1): string {
    return this.str.substring(this.cursor, howMuchMore);
  }

  private spyRegExp(pattern: RegExp): string {
    const matches = String(this).match(pattern);
    return matches && matches.length && matches[0] || '';
  }

  /**
   * Move the cursor that's iterating the string
   */
  private addCursorRegExp(pattern: RegExp): string {
    if (!String(pattern).match(/^\/\^/)) {
      throw new Error(
        `all regexp used to move the cursor in the iterable string must start with ^. Entry regex: "${String(pattern)}"`
      );
    }

    const match = this.spyRegExp(pattern);

    return this.addCursorNumeric(match.length || 0);
  }

  /**
   * If find an match with the regexp argument, it return the match and move the cursor
   */
  private addCursorNumeric(howMuchMore = 1): string {
    const piece = this.spyNumeric(howMuchMore);
    this.cursor += howMuchMore;

    return piece;
  }

  endContent(): boolean {
    return this.end() || !!this.spy(/^\s*$/, false);
  }

  end(): boolean {
    return this.str.length <= this.cursor;
  }
}

class AlgorithmNotSuported extends Error {

}


class InvalidURIEncrypted extends Error {

}
