import { IterableString } from '@belomonte/iterable-string';

export type TURIParams = {
  [param: string]: string
};

export type TEncryptedURIKDFConfig = {

  /**
   * Only pbkdf2 supported, just if someone see purpose in alternative KDF,
   * if you need this come to me, open an issue
   * 
   * @default pbkdf2
   */
  kdf?: 'pbkdf2',

  /**
   * If you want your custom parameters for key derivation function
   * and want it included in the generated URI.
   *
   * @default true
   */
  includeURIParams?: boolean;

  /**
   * Enableable just if `includeURIParams` is set as `true`.
   *
   * If set as `true` ignore the param if the value is the default
   * value, include only non default params.
   *
   * If set as `false` all included param in kdf object will be
   * include in URI with his reserved name.
   * 
   * @default true
   */
  ignoreDefaults?: boolean;

  /**
   * Hashing algorithm supported by pbkdf2
   * 
   * @default sha256
   */
  hasher?: string;

  /**
   * Iterations of hashing for pbkdf2
   * 
   * @default 32
   */
  rounds?: number;

  /**
   * Derivate key length for pbkdf2
   * 
   * @default 32
   */
  derivateKeyLength?: number;
};

class EncryptedURISyntaxMatcher {
  match(uri: string): boolean {
    return /^encrypted:/.test(uri);
  }
}

/**
 * When the uri is still being interpreted
 * and has not yet gone through validation
 */
export type TEncryptedURI<T extends TURIParams> = {
  algorithm?: string;
  queryString?: string;

  /**
   * bytes of cipher into base64, it could include the 'Salted__' header.
   */
  cipher: string;
  params?: TEncryptedURIParams<T>;
};

class EncryptedURIDecoder<T extends TURIParams> {

  static readonly defaultConfigs: Required<TEncryptedURIKDFConfig> = {
    kdf: 'pbkdf2',
    hasher: 'sha256',
    ignoreDefaults: true,
    includeURIParams: true,
    derivateKeyLength: 32,
    rounds: 32
  };

  static getKDFConfig<T extends TURIParams>(
    configOverload?: TEncryptedURIKDFConfig | TEncryptedURI<T>
  ): Required<TEncryptedURIKDFConfig> {
    let config: TEncryptedURIKDFConfig = this.defaultConfigs;
    if (configOverload && 'params' in configOverload) {
      config = this.castParamsToConfig(configOverload.params);
    }
  
    const configWithDefaults: Required<TEncryptedURIKDFConfig> = {
      ...this.defaultConfigs,
      ...config
    };
  
    return configWithDefaults;
  }
  
  private static castParamsToConfig<T extends TURIParams>(
    params?: TEncryptedURIParams<T>
  ): TEncryptedURIKDFConfig {
    const config: TEncryptedURIKDFConfig = {};
  
    if (!params) {
      return config;
    }
  
    if (typeof params.kdf === 'string') {
      config.kdf = params.kdf as 'pbkdf2';
    }
  
    if (typeof params.h === 'string') {
      config.hasher = params.h;
    }
  
    if (typeof params.dklen === 'string') {
      const derivateKeyLength = Number(params.dklen);
      if (Number.isSafeInteger(derivateKeyLength)) {
        config.derivateKeyLength = derivateKeyLength;
      }
    }
  
    if (typeof params.c === 'string') {
      const rounds = Number(params.c);
      if (Number.isSafeInteger(rounds)) {
        config.rounds = rounds;
      }
    }
  
    return config;
  }

  private readonly ENCRYPTED_URI_MATCHER = /^encrypted:/;
  private readonly QUERY_STRING_MATCHER = /^\?[^;]*;/;

  decode(content: string): TEncryptedURI<T> {
    const resultset: TEncryptedURI<T> = { cipher: '' };
    const iterable = new IterableString(content);

    this.checkURI(iterable);
    this.identifyAlgorithm(iterable, resultset);
    this.readQueryString(iterable, resultset);
    resultset.cipher = iterable.toTheEnd().replace(/^;/, '');

    return resultset;
  }

  private checkURI(iterable: IterableString): void {
    const is = iterable.addCursor(this.ENCRYPTED_URI_MATCHER);
    if (!is) {
      throw new Error('not an encrypted uri');
    }
  }

  private identifyAlgorithm(iterable: IterableString, resultset: TEncryptedURI<T>): void {
    const algorithmMatcher = /^[^?;]*/;
    const algorithmValue = iterable.addCursor(algorithmMatcher);

    if (algorithmValue) {
      resultset.algorithm = algorithmValue;
    }
  }

  private readQueryString(iterable: IterableString, resultset: TEncryptedURI<T>): void {
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
        }) as TEncryptedURIParams<T>;
      }
    }
  }
}

class EncryptedURIEncoder<T extends TURIParams> {

  encode(content: TEncryptedURI<T> & { kdf?: TEncryptedURIKDFConfig }): string {
    const algorithm = this.encodeAlgorithm(content);
    const parameters = this.encodeParameters(content);

    if (parameters) {
      return `encrypted:${algorithm}?${parameters};${content.cipher}`;
    } else {
      return `encrypted:${algorithm};${content.cipher}`;
    }
  }

  private encodeParameters(
    content: TEncryptedURI<T> & { kdf?: TEncryptedURIKDFConfig }
  ): string {
    const params: TURIParams = {};
    const kdfParams = this.castKDFConfigToParams(content);
    const contentParams: TURIParams = { ...content.params, ...kdfParams };
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

  private castKDFConfigToParams(
    content: TEncryptedURI<T> & { kdf?: TEncryptedURIKDFConfig }
  ): TEncryptedURIParams<TURIParams> {
    //  TODO: cast kdf config into params
  }

  private encodeAlgorithm(
    content: TEncryptedURI<T>
  ): string {
    return content.algorithm || '';
  }
}

export class EncryptedURIParser<T extends TURIParams> {

  static matcher(uri: string): boolean {
    return new EncryptedURISyntaxMatcher().match(uri);
  }

  readonly encoded: string;
  readonly decoded: TEncryptedURI<T>;

  constructor(content: TEncryptedURI<T>);
  constructor(content: string);
  constructor(content: string | TEncryptedURI<T>) {
    if (typeof content === 'string') {
      const decoder = new EncryptedURIDecoder<T>();
      this.decoded = decoder.decode(this.encoded = content);
      this.encoded = content;
    } else {
      const encoder = new EncryptedURIEncoder();
      this.decoded = content;
      this.encoded = encoder.encode(content);
    }
  }
}

export abstract class EncryptedURIEncrypter<
  T extends TURIParams
> {

  constructor(protected params: TEncryptedURIResultset<T>) { }
  
  abstract encrypt(): Promise<TEncryptedURI<T>>;
}

export abstract class EncryptedURIDecrypter<T extends TURIParams> {

  constructor(
    protected decoded: TEncryptedURI<T>
  ) { }

  abstract decrypt(): Promise<string>;
}

/**
 * This type represent the reserved URI params into the
 * string serialized version. This type represents the
 * params as is after read from query params
 */
export type TEncryptedURIParams<T extends TURIParams> = {
  [attr: string]: string;
} & {

  /**
   * key derivation function
   * @default 'pbkdf2'
   */
  kdf?: string;

  /**
   * derivated key length serialized as string
   * this is a pbkdf2 kdf param
   *
   * @default '32'
   */
  dklen?: string;

  /**
   * number of counts, rounds serialized as string
   * this is a pbkdf2 kdf param
   * 
   * @default '1'
   */
  c?: string;

  /**
   * h, algorithm for hasher
   * this is a pbkdf2 kdf param
   * 
   * @default 'sha256'
   */
  h?: string;
} & {

  /**
   * s, salt parameter expected in hex string format
   *
   * mandatory, as default it is a random number and is not send
   * as URI param, but as 'Salted__' header in the cipher, if 's'
   * is set, the 'Salted__' header will be removed
   *  
   * this is a pbkdf2 kdf param 
   */
  s?: string;
} & T;

export type TEncryptedURIDefaultParams<T extends TURIParams> = {
  algorithm?: string;

  /**
   * Customize the key derivation function params to open and to encrypt,
   * you can configure in this object to include the kdf as URI params 
   */
  kdf?: TEncryptedURIKDFConfig;

  params: T;
};

export type TEncryptedURIEncryptedDefaultParams<T extends TURIParams> = {
  cipher: string;
} & TEncryptedURIDefaultParams<T>;

export type TEncryptedURIEncryptableDefaultParams<T extends TURIParams> = {
  content: string;
  password: string;
} & TEncryptedURIDefaultParams<T>;

export type TEncrypterClass<T extends TURIParams> = { new (resultset: TEncryptedURIResultset<T>, ...args: any[]): EncryptedURIEncrypter<any> } & { algorithm?: string };
export type TDecrypterClass<T extends TURIParams> = { new (decoded: TEncryptedURI<T>, ...args: any[]): EncryptedURIDecrypter<T> };
export type TEncryptedURIResultset<T extends TURIParams> = TEncryptedURIEncryptableDefaultParams<T>;

export function EncryptedURIAlgorithm<T extends TURIParams>(args: {
  algorithm: string,
  decrypter: TDecrypterClass<T>
}) {
  return function (
    target: TEncrypterClass<T> & { algorithm?: string }
  ) {
    target.algorithm = args.algorithm;
    EncryptedURI.setAlgorithm(args.algorithm, target, args.decrypter);
  };
}

export class EncryptedURI {

  static readonly DEFAULT_ALGORITHM = 'aes';

  static readonly supportedAlgorithm: {
    [algorithm: string]: [
      TEncrypterClass<any>,
      TDecrypterClass<any>
    ]
  } = { };

  static matcher(uri: string): boolean {
    return new EncryptedURISyntaxMatcher().match(uri);
  }

  static encode<T extends TURIParams>(params: TEncryptedURI<T>): string {
    return new EncryptedURIParser(params).encoded;
  }

  static async encrypt<T extends TURIParams>(params: TEncryptedURIEncryptableDefaultParams<T>, ...args: any[]): Promise<string> {
    const [ encrypter ] = this.getAlgorithm(params.algorithm);
    const ciphred = await new encrypter(params, ...args).encrypt();
    ciphred.algorithm = encrypter.algorithm || params.algorithm;

    return Promise.resolve(this.encode(ciphred));
  }

  static decrypt(uri: string, password: string): Promise<string>;
  static decrypt(uri: string, ...args: any[]): Promise<string> {
    const uriDecoded = new EncryptedURIParser(uri).decoded;
    const [ , decryptor ] = this.getAlgorithm(uriDecoded.algorithm);
    return new decryptor(uriDecoded, ...args).decrypt();
  }

  static setAlgorithm<T extends TURIParams>(
    algorithm: string,
    encrypter: TEncrypterClass<T>,
    decrypter: TDecrypterClass<T>
  ): void {
    if (!this.supportedAlgorithm[algorithm]) {
      this.supportedAlgorithm[algorithm] = [encrypter, decrypter];
    }
  }

  private static getAlgorithm(algorithm?: string): [
    TEncrypterClass<any>,
    TDecrypterClass<any>
  ] {
    algorithm = algorithm || EncryptedURI.DEFAULT_ALGORITHM;
    const [ encryptor, decryptor ] = this.supportedAlgorithm[algorithm] || [ null, null];
    if (!encryptor && !decryptor) {
      throw new Error(`Algorithm '${algorithm}' not supported`);
    }

    return [ encryptor, decryptor ];
  }
}
