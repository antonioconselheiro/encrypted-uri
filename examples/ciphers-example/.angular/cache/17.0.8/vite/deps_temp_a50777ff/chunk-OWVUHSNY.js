// node_modules/@encrypted-uri/core/index.js
var IterableString = class {
  constructor(str) {
    this.str = str;
    this.cursor = 0;
    this.DEBUG_CHARS_PREVIEW = 100;
  }
  get debugInfo() {
    return String(this).substring(0, this.DEBUG_CHARS_PREVIEW);
  }
  get currenPosition() {
    return this.cursor;
  }
  /**
   * Return the string in it current cursor position
   */
  toString() {
    return this.str.substring(this.cursor);
  }
  valueOf() {
    return this.str.substring(this.cursor);
  }
  /**
   * Return the original string
   */
  getOriginalString() {
    return this.str;
  }
  /**
   * Move the cursor and return the result
   */
  addCursor(param, autoTrimResult = true) {
    let result = "";
    if (typeof param === "number") {
      result = this.addCursorNumeric(param);
    } else if (typeof param === "string") {
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
  spy(param, autoTrimResult = true) {
    let result = "";
    if (typeof param === "number") {
      result = this.spyNumeric(param);
    } else if (typeof param === "string") {
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
  spyNumeric(howMuchMore = 1) {
    return this.str.substring(this.cursor, this.cursor + howMuchMore);
  }
  spyRegExp(pattern) {
    const matches = String(this).match(pattern);
    return matches && matches.length && matches[0] || "";
  }
  /**
   * Move the cursor that's iterating the string
   */
  addCursorRegExp(pattern) {
    if (!String(pattern).match(/^\/\^/)) {
      throw new Error(`all regexp used to move the cursor in the iterable string must start with ^. Entry regex: "${String(pattern)}"`);
    }
    const match = this.spyRegExp(pattern);
    return this.addCursorNumeric(match.length || 0);
  }
  /**
   * If find an match with the regexp argument, it return the match and move the cursor
   */
  addCursorNumeric(howMuchMore = 1) {
    const piece = this.spyNumeric(howMuchMore);
    this.cursor += howMuchMore;
    return piece;
  }
  toTheEnd() {
    const content = this.str.substring(this.cursor);
    this.cursor += content.length;
    return content;
  }
  endContent() {
    return this.end() || !!this.spy(/^\s*$/, false);
  }
  end() {
    return this.str.length <= this.cursor;
  }
};
var URIEncryptedSyntaxMatcher = class {
  match(uri) {
    return /^encrypted:/.test(uri);
  }
};
var URIEncryptedDecoder = class {
  constructor() {
    this.ENCRYPTED_URI_MATCHER = /^encrypted:/;
    this.QUERY_STRING_MATCHER = /^\?[^;]*;/;
  }
  decode(content) {
    const resultset = { cypher: "" };
    const iterable = new IterableString(content);
    this.checkURI(iterable);
    this.identifyAlgorithm(iterable, resultset);
    this.readQueryString(iterable, resultset);
    resultset.cypher = iterable.toTheEnd().replace(/^;/, "");
    return resultset;
  }
  checkURI(iterable) {
    const is = iterable.addCursor(this.ENCRYPTED_URI_MATCHER);
    if (!is) {
      throw new Error("not an encrypted uri");
    }
  }
  identifyAlgorithm(iterable, resultset) {
    const algorithmMatcher = /^[^?;]*/;
    const algorithmValue = iterable.addCursor(algorithmMatcher);
    if (algorithmValue) {
      resultset.algorithm = algorithmValue;
    }
  }
  readQueryString(iterable, resultset) {
    const parametersMatcher = /^\?([^=]+=[^=]+)(&([^=]+=[^=]+))*[;]$/;
    const queryString = iterable.addCursor(this.QUERY_STRING_MATCHER);
    const cleanQueryString = queryString.replace(/^\?|;$/g, "");
    resultset.queryString = cleanQueryString;
    if (parametersMatcher.test(queryString)) {
      const decodedQueryParams = new URL(`encrypted://_?${cleanQueryString}`);
      const paramsList = Array.from(decodedQueryParams.searchParams.entries()).map(([key, value]) => ({ [key]: decodeURI(String(value)) }));
      if (paramsList.length) {
        resultset.params = paramsList.reduce((result, object) => {
          Object.keys(object).forEach((key) => result[key] = object[key]);
          return result;
        });
      }
    }
  }
};
var URIEncryptedEncoder = class {
  encode(content) {
    const algorithm = this.encodeAlgorithm(content);
    const parameters = this.encodeParameters(content);
    if (parameters) {
      return `encrypted:${algorithm}?${parameters};${content.cypher}`;
    } else {
      return `encrypted:${algorithm};${content.cypher}`;
    }
  }
  encodeParameters(content) {
    const params = {};
    const contentParams = content.params || {};
    const paramsKeys = Object.keys(contentParams);
    if (paramsKeys.length) {
      paramsKeys.forEach((key) => params[key] = contentParams[key]);
    } else {
      return content.queryString || "";
    }
    const serializer = new URLSearchParams();
    paramsKeys.forEach((key) => serializer.append(key, params[key]));
    return serializer.toString();
  }
  encodeAlgorithm(content) {
    return content.algorithm || "";
  }
};
var URIEncryptedParser = class {
  static matcher(uri) {
    return new URIEncryptedSyntaxMatcher().match(uri);
  }
  constructor(content) {
    if (typeof content === "string") {
      const decoder = new URIEncryptedDecoder();
      this.decoded = decoder.decode(this.encoded = content);
      this.encoded = content;
    } else {
      const encoder = new URIEncryptedEncoder();
      this.decoded = content;
      this.encoded = encoder.encode(content);
    }
  }
};
var EncryptedURIEncrypter = class {
  constructor(params) {
    this.params = params;
  }
};
var EncryptedURIDecrypter = class {
  constructor(decoded) {
    this.decoded = decoded;
  }
};
var EncryptedURI = class _EncryptedURI {
  static matcher(uri) {
    return new URIEncryptedSyntaxMatcher().match(uri);
  }
  static encode(params) {
    return new URIEncryptedParser(params).encoded;
  }
  static encrypt(params, ...args) {
    const [encryptor] = this.getAlgorithm(params.algorithm);
    return this.encode(new encryptor(params, ...args).encrypt());
  }
  static decrypt(uri, ...args) {
    const uriDecoded = new URIEncryptedParser(uri).decoded;
    const [, decryptor] = this.getAlgorithm(uriDecoded.algorithm);
    return new decryptor(uriDecoded, ...args).decrypt();
  }
  static setAlgorithm(algorithm, encrypter, decrypter) {
    this.supportedAlgorithm[algorithm] = [encrypter, decrypter];
  }
  static getAlgorithm(algorithm) {
    algorithm = algorithm || _EncryptedURI.DEFAULT_ALGORITHM;
    const [encryptor, decryptor] = this.supportedAlgorithm[algorithm] || [null, null];
    if (!encryptor && !decryptor) {
      throw new Error(`Algorithm '${algorithm}' not supported`);
    }
    return [encryptor, decryptor];
  }
};
EncryptedURI.DEFAULT_ALGORITHM = "aes";
EncryptedURI.supportedAlgorithm = {};

export {
  IterableString,
  URIEncryptedParser,
  EncryptedURIEncrypter,
  EncryptedURIDecrypter,
  EncryptedURI
};
//# sourceMappingURL=chunk-OWVUHSNY.js.map
