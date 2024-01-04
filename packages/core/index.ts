export type TEncryptedURIParams = {
  [attr: string]: string;
}

/**
 * When the uri is still being interpreted
 * and has not yet gone through validation
 */
export type TEncryptedURI<T extends TEncryptedURIParams = TEncryptedURIParams> = {
  algorithm?: string;
  queryString?: string;
  cipher: string;
  params?: T;
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

class EncryptedURISyntaxMatcher {
  match(uri: string): boolean {
    return /^encrypted:/.test(uri);
  }
}

class URIEncryptedDecoder {

  private readonly ENCRYPTED_URI_MATCHER = /^encrypted:/;
  private readonly QUERY_STRING_MATCHER = /^\?[^;]*;/;

  decode(content: string): TEncryptedURI {
    const resultset: TEncryptedURI = { cipher: '' };
    const iterable = new IterableString(content);

    this.checkURI(iterable);
    this.identifyAlgorithm(iterable, resultset);
    this.readQueryString(iterable, resultset);
    resultset.cipher = iterable.toTheEnd().replace(/^;/, '');

    return resultset as TEncryptedURI;
  }

  private checkURI(iterable: IterableString): void {
    const is = iterable.addCursor(this.ENCRYPTED_URI_MATCHER);
    if (!is) {
      throw new Error('not an encrypted uri');
    }
  }

  private identifyAlgorithm(iterable: IterableString, resultset: TEncryptedURI): void {
    const algorithmMatcher = /^[^?;]*/;
    const algorithmValue = iterable.addCursor(algorithmMatcher);

    if (algorithmValue) {
      resultset.algorithm = algorithmValue;
    }
  }

  private readQueryString(iterable: IterableString, resultset: TEncryptedURI): void {
    const parametersMatcher = /^\?([^=]+=[^=]+)(&([^=]+=[^=]+))*[;]$/;
    const queryString = iterable.addCursor(this.QUERY_STRING_MATCHER);
    const cleanQueryString = queryString.replace(/^\?|;$/g, '');
    resultset.queryString = cleanQueryString;

    if (parametersMatcher.test(queryString)) {
      const decodedQueryParams = new URL(`encrypted://_?${cleanQueryString}`);
      const paramsList = Array
        .from(decodedQueryParams.searchParams.entries())
        .map(([key, value]) => ({ [key]: decodeURI(String(value)) }));

      if (paramsList.length) {
        resultset.params = paramsList.reduce((result, object) => {
          Object.keys(object).forEach(key => result[key] = object[key]);
          return result;
        });
      }
    }
  }
}

class URIEncryptedEncoder {

  encode(content: TEncryptedURI): string {
    const algorithm = this.encodeAlgorithm(content);
    const parameters = this.encodeParameters(content);

    if (parameters) {
      return `encrypted:${algorithm}?${parameters};${content.cipher}`;
    } else {
      return `encrypted:${algorithm};${content.cipher}`;
    }
  }

  private encodeParameters(
    content: TEncryptedURI
  ): string {
    const params: { [attr: string]: string } = {};
    const contentParams = content.params || {};
    const paramsKeys = Object.keys(contentParams);
    if (paramsKeys.length) {
      paramsKeys.forEach(key => params[key] = contentParams[key]);
    } else {
      return content.queryString || '';
    }

    const serializer = new URLSearchParams();
    paramsKeys.forEach(key => serializer.append(key, params[key]));

    return serializer.toString();
  }

  private encodeAlgorithm(
    content: TEncryptedURI
  ): string {
    return content.algorithm || '';
  }
}

export class EncryptedURIParser {

  static matcher(uri: string): boolean {
    return new EncryptedURISyntaxMatcher().match(uri);
  }

  readonly encoded: string;
  readonly decoded: TEncryptedURI;

  constructor(content: TEncryptedURI);
  constructor(content: string);
  constructor(content: string | TEncryptedURI) {
    if (typeof content === 'string') {
      const decoder = new URIEncryptedDecoder();
      this.decoded = decoder.decode(this.encoded = content);
      this.encoded = content;
    } else {
      const encoder = new URIEncryptedEncoder();
      this.decoded = content;
      this.encoded = encoder.encode(content);
    }
  }
}

export abstract class EncryptedURIEncrypter<T extends TEncryptedURIEncryptableDefaultParams = TEncryptedURIEncryptableDefaultParams> {

  constructor(protected params: T) { }
  
  abstract encrypt(): Promise<TEncryptedURI>;
}

export abstract class EncryptedURIDecrypter<T extends TEncryptedURI = TEncryptedURI> {

  constructor(
    protected decoded: T
  ) { }

  abstract decrypt(): Promise<string>;
}

export type TEncryptedURIDefaultParams = {
  algorithm?: string;
  [param: string]: any;
}

export type TEncryptedURIEncryptedDefaultParams = {
  cipher: string;
} & TEncryptedURIDefaultParams;

export type TEncryptedURIEncryptableDefaultParams = {
  content: string;
  key: string;
} & TEncryptedURIDefaultParams;

export class EncryptedURI {

  static readonly DEFAULT_ALGORITHM = 'aes';

  static readonly supportedAlgorithm: {
    [algorithm: string]: [
      { new (...args: any[]): EncryptedURIEncrypter<any> },
      { new (...args: any[]): EncryptedURIDecrypter<any> }
    ]
  } = { }

  static matcher(uri: string): boolean {
    return new EncryptedURISyntaxMatcher().match(uri);
  }

  static encode(params: TEncryptedURI): string {
    return new EncryptedURIParser(params).encoded;
  }

  static async encrypt(params: TEncryptedURIEncryptableDefaultParams, ...args: any[]): Promise<string> {
    const [ encryptor ] = this.getAlgorithm(params.algorithm);
    const ciphred = await new encryptor(params, ...args).encrypt();
    return Promise.resolve(this.encode(ciphred));
  }

  static decrypt(uri: string, key: string): Promise<string>;
  static decrypt(uri: string, ...args: any[]): Promise<string> {
    const uriDecoded = new EncryptedURIParser(uri).decoded;
    const [ , decryptor ] = this.getAlgorithm(uriDecoded.algorithm);
    return new decryptor(uriDecoded, ...args).decrypt();
  }

  static setAlgorithm<T extends TEncryptedURI>(
    algorithm: string,
    encrypter: { new (...args: any[]): EncryptedURIEncrypter },
    decrypter: { new (decoded: T, ...args: any[]): EncryptedURIDecrypter<T> }
  ): void {
    this.supportedAlgorithm[algorithm] = [encrypter, decrypter];
  }

  private static getAlgorithm(algorithm?: string): [
    { new (...args: any[]): EncryptedURIEncrypter },
    { new (decoded: TEncryptedURI, ...args: any[]): EncryptedURIDecrypter }
  ] {
    algorithm = algorithm || EncryptedURI.DEFAULT_ALGORITHM;
    const [ encryptor, decryptor ] = this.supportedAlgorithm[algorithm] || [ null, null];
    if (!encryptor && !decryptor) {
      throw new Error(`Algorithm '${algorithm}' not supported`);
    }

    return [ encryptor, decryptor ];
  }
}
