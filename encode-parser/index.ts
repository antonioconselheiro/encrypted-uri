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

    if (algorithmValue) {
      resultset.algorithm = algorithmValue;
    }
  }

  private identifyOperationMode(iterable: IterableString, resultset: TEncryptedURI): void {
    const operationModeMatcher = /^\/[^?;]+/;
    const hasOperationMode = iterable.addCursor(operationModeMatcher);
    if (hasOperationMode) {
      resultset.mode = this.removeNotAlphaNumerical(hasOperationMode);
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

  private removeNotAlphaNumerical(content: string): string {
    return content.replace(/[^a-z\d]/g, '');
  }
}

class URIEncryptedEncode {

  encode(content: TEncryptedURI): string {
    const algorithm = this.encodeAlgorithmAndMode(content);
    const parameters = this.encodeParameters(content);

    return `encrypted:${algorithm}?${parameters};${content.cypher}`;
  }

  private encodeParameters(
    content: TEncryptedURI
  ): string {
    const params: { [attr: string]: string } = {};
    const contentParams = content.params || {};
    const paramsKeys = Object.keys(contentParams);
    let lastAttributeValue = '';
    if (paramsKeys.length) {
      paramsKeys.forEach(key => lastAttributeValue = params[key] = contentParams[key]);
    } else {
      return content.queryString || '';
    }

    const serializer = new URLSearchParams();
    paramsKeys.forEach(key => serializer.append(key, params[key]));

    return serializer.toString();
  }

  private encodeAlgorithmAndMode(
    content: TEncryptedURI
  ): string {
    if (content.algorithm && content.mode) {
      return `${content.algorithm}/${content.mode}`;
    }

    return content.algorithm || '';
  }
}

export class URIEncrypted {

  static matcher(uri: string): boolean {
    return new URIEncryptedSyntaxMatcher().match(uri);
  }

  readonly encoded: string;
  readonly decoded: TEncryptedURI;

  constructor(content: TEncryptedURI);
  constructor(content: string);
  constructor(content: string | TEncryptedURI) {
    if (typeof content === 'string') {
      const decoder = new URIEncryptedDecode();
      this.decoded = decoder.decode(this.encoded = content);
      this.encoded = content;
    } else {
      const encoder = new URIEncryptedEncode();
      this.decoded = content;
      this.encoded = encoder.encode(content);
    }
  }
}
