/**
 * When the uri is still being interpreted
 * and has not yet gone through validation
 */
type TEncryptedURI = {
  algorithm?: string;
  mode?: string;
  queryString?: string;
  cypher?: string;
  params?: {
    [attr: string]: string;
  }
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
   * 
   * @default false
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
   * 
   * @default false
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

class InvalidURIEncrypted extends Error {

}

export class IterableString {

  private cursor = 0;
  private readonly DEBUG_CHARS_PREVIEW = 100;

  constructor(
    private str: string
  ) {
  }

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
    return this.str.substring(this.cursor, this.cursor + howMuchMore);
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

  toTheEnd(): string {
    const content = this.str.substring(this.cursor);
    this.cursor += content.length;
    return content;
  }

  endContent(): boolean {
    return this.end() || !!this.spy(/^\s*$/, false);
  }

  end(): boolean {
    return this.str.length <= this.cursor;
  }
}

const URIEncryptedDefaults = {
  DEFAULT_ALGORITHM: 'aes',
  DEFAULT_AES_MODE: 'cbc',
  DEFAULT_AES_PADDING: 'pkcs7'
};

class URIEncryptedSyntaxMatcher {
  match(uri: string): boolean {
    return /^encrypted:/.test(uri);
  }
}

class URIEncryptedDecode {

  private readonly ENCRYPTED_URI_MATCHER = /^encrypted:/;
  private readonly QUERY_STRING_MATCHER = /^\?[^;]*;/;

  decode(content: string): TEncryptedURI {
    const resultset: TEncryptedURI = {};
    const iterable = new IterableString(content);

    this.checkURI(iterable);
    this.identifyAlgorithm(iterable, resultset);
    this.identifyOperationMode(iterable, resultset);
    this.readQueryString(iterable, resultset);
    resultset.cypher = iterable.toTheEnd();

    return resultset as TEncryptedURI;
  }

  private checkURI(iterable: IterableString): void {
    const is = iterable.addCursor(this.ENCRYPTED_URI_MATCHER);
    if (!is) {
      throw new InvalidURIEncrypted('not an encrypted uri');
    }
  }

  private identifyAlgorithm(iterable: IterableString, resultset: TEncryptedURI): void {
    const algorithmMatcher = /^[^/?;]*/;
    const algorithmValue = iterable.addCursor(algorithmMatcher);

    resultset.algorithm = algorithmValue;
    if (!algorithmValue) {
      resultset.algorithm = URIEncryptedDefaults.DEFAULT_ALGORITHM;
    }
  }

  private identifyOperationMode(iterable: IterableString, resultset: TEncryptedURI): void {
    const operationModeMatcher = /^\/[^?;]+/;
    const hasOperationMode = iterable.addCursor(operationModeMatcher);
    if (hasOperationMode) {
      resultset.mode = this.removeNotAlphaNumerical(hasOperationMode);
    }

    if (!resultset.mode && resultset.algorithm === URIEncryptedDefaults.DEFAULT_ALGORITHM) {
      resultset.mode = URIEncryptedDefaults.DEFAULT_AES_MODE;
    }
  }

  private readQueryString(iterable: IterableString, resultset: TEncryptedURI): void {
    const parametersMatcher = /^\?([^=]+=[^=]+)(&([^=]+=[^=]+))*[;]$/;
    const queryString = iterable.addCursor(this.QUERY_STRING_MATCHER);
    const cleanQueryString = queryString.replace(/^\?|;$/g, '');
    resultset.queryString = cleanQueryString;

    if (parametersMatcher.test(queryString)) {
      const decodedQueryParams = new URL(`encrypted://_${cleanQueryString}`);
      resultset.params = Array
        .from(decodedQueryParams.searchParams.entries())
        .map(([key, value]) => ({ [key]: decodeURI(String(value)) }))
        .reduce((result, object) => {
          Object.keys(object).forEach(key => result[key] = object[key]);
          return result;
        });
    }
  }

  private removeNotAlphaNumerical(content: string): string {
    return content.replace(/[^a-z\d]/g, '');
  }
}

class URIEncryptedEncode {

  encode(content: TEncryptedURI, config?: TEncryptedURIConfig): string {
    const algorithm = this.encodeAlgorithmAndMode(content, config);
    const parameters = this.encodeParameters(content, config);

    return `encrypted:${algorithm}?${parameters};${content.cypher}`;
  }

  private encodeParameters(
    content: TEncryptedURI,
    config?: TEncryptedURIConfig
  ): string {
    const {
      alwaysIncludePadding,
      alwaysIncludeDefaultArgumentName
    } = this.normalizeConfig(config);

    const params: { [attr: string]: string } = {};
    const contentParams = content.params || {};
    const paramsKeys = Object.keys(contentParams);
    let lastAttributeValue = '';
    if (paramsKeys.length) {
      paramsKeys.forEach(key => {
        const isPadding = key === 'pad';
        const ignoreDefaultPadding = !alwaysIncludePadding;
        const isDefaultValueSelected = contentParams[key] === URIEncryptedDefaults.DEFAULT_AES_PADDING;

        if (!isPadding || !ignoreDefaultPadding || !isDefaultValueSelected) {
          lastAttributeValue = params[key] = contentParams[key];
        }
      });
    }

    if (alwaysIncludeDefaultArgumentName && Object.keys(params).length === 1) {
      return lastAttributeValue;
    } else {
      const serializer = new URLSearchParams();
      paramsKeys.forEach(key => serializer.append(key, params[key]));

      return serializer.toString();
    }
  }

  private encodeAlgorithmAndMode(
    content: TEncryptedURI,
    config?: TEncryptedURIConfig
  ): string {
    const {
      alwaysIncludeAlgorithm,
      alwaysIncludeMode
    } = this.normalizeConfig(config);

    let algorithm = content.algorithm || '';
    if (content.algorithm === 'aes') {
      if (alwaysIncludeAlgorithm) {
        const isDefaultMode = content.mode === URIEncryptedDefaults.DEFAULT_AES_MODE;
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
    const includeDefaults = this.readConfig(config, 'includeDefaults');

    const alwaysIncludeAlgorithm = includeDefaults ||
      this.readConfig(config, 'alwaysIncludeAlgorithm');

    const alwaysIncludePadding = includeDefaults ||
      this.readConfig(config, 'alwaysIncludePadding');

    const alwaysIncludeMode = includeDefaults ||
      this.readConfig(config, 'alwaysIncludeMode');

    const alwaysIncludeDefaultArgumentName = includeDefaults ||
      this.readConfig(config, 'alwaysIncludeDefaultArgumentName');

    return {
      alwaysIncludeAlgorithm,
      alwaysIncludePadding,
      alwaysIncludeMode,
      alwaysIncludeDefaultArgumentName
    }
  }

  private readConfig(config: { [attr: string]: boolean } | undefined, configName: string): boolean {
    return config &&
      configName in config &&
      config[configName]
      || false;
  }
}

export class URIEncrypted {

  static matcher(uri: string): boolean {
    return new URIEncryptedSyntaxMatcher().match(uri);
  }

  readonly encoded: string;
  readonly decoded: TEncryptedURI;

  constructor(content: TEncryptedURI, config?: TEncryptedURIConfig);
  constructor(content: string);
  constructor(
    content: string | TEncryptedURI,
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
