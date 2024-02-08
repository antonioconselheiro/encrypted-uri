/* eslint-disable max-lines */
/**
 * FIXME: desmembrar arquivos do projeto em arquivos individuais para
 * cada simbolo respeitando o princípio de responsabilidade única e
 * garantindo que somente os simbolos utilizados sejam carregados nos
 * projetos que incluirem esta dependência
*/
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

  static getKDFConfig<T extends TURIParams>(
    /**
     * if you're decoding pass TEncryptedURI<T>,
     * if you're encoding pass TEncryptedURIResultset<T>
     * 
     * @optional
     */
    kdfConfig?: TEncryptedURI<T> | TEncryptedURIResultset<T>,

    /**
     * If your application customize default values
     * 
     * @optional
     */
    kdfDefaultConfig?: TEncryptedURIKDFConfig
  ): Required<TEncryptedURIKDFConfig> {
    let config: TEncryptedURIKDFConfig = EncryptedURI.defaultConfigs;
    if (kdfConfig) {
      config = this.castParamsToConfig(kdfConfig.params);
    }
    
    const configWithDefaults: Required<TEncryptedURIKDFConfig> = {
      ...EncryptedURI.defaultConfigs,
      ...kdfDefaultConfig,
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
      const params: TURIParams = {};

      decodedQueryParams.searchParams.forEach((value, key) => {
        params[key] = decodeURI(String(value));
      });

      if (Object.keys(params).length) {
        resultset.params = params as TEncryptedURIParams<T>;
      }
    }
  }
}

class EncryptedURIEncoder<T extends TURIParams> {

  private static propertyShouldBeIgnored(
    configs: TEncryptedURIKDFConfig,
    configName: keyof TEncryptedURIKDFConfig,
    overridingDefaultConfig?: TEncryptedURIKDFConfig
  ): boolean {
    const defaultConfigs = { ...EncryptedURI.defaultConfigs, ...overridingDefaultConfig };
    if (
      configs[configName] &&
      defaultConfigs[configName] === configs[configName] &&
      configs.ignoreDefaults
    ) {
      console.info(configName, 'ignored');
      return true; 
    }

    console.info(configName, 'included');
    return false;
  }

  static castKDFConfigToParams(
    content: { kdf?: TEncryptedURIKDFConfig },
    overridingDefaultConfig?: TEncryptedURIKDFConfig
  ): TEncryptedURIParams<TURIParams> {
    const params: TEncryptedURIParams<TURIParams> = {};

    if (content.kdf) {
      if (!this.propertyShouldBeIgnored(content.kdf, 'kdf', overridingDefaultConfig)) {
        params.kdf = content.kdf.kdf;
      }

      if (!this.propertyShouldBeIgnored(content.kdf, 'hasher', overridingDefaultConfig)) {
        params.h = content.kdf.hasher;
      }

      if (!this.propertyShouldBeIgnored(content.kdf, 'derivateKeyLength', overridingDefaultConfig)) {
        params.dklen = String(content.kdf.derivateKeyLength);
      }

      if (!this.propertyShouldBeIgnored(content.kdf, 'rounds', overridingDefaultConfig)) {
        params.c = String(content.kdf.rounds);
      }
    }

    return params;
  }

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
    const kdfParams = EncryptedURIEncoder.castKDFConfigToParams(content);
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

  constructor(
    protected params: TEncryptedURIResultset<T>,
    protected defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) { }
  
  abstract encrypt(): Promise<TEncryptedURI<T>>;
}

export abstract class EncryptedURIDecrypter<T extends TURIParams> {

  protected kdf: Required<TEncryptedURIKDFConfig>;

  constructor(
    protected decoded: TEncryptedURI<T>,
    protected password: string,
    protected defaultsKDF: Required<TEncryptedURIKDFConfig>
  ) {
    this.kdf = this.getKDFConfig(this.decoded, this.defaultsKDF);
  }

  abstract decrypt(): Promise<string>;

  private getKDFConfig(
    kdfConfig: TEncryptedURI<T>,
    kdfDefaultConfig: TEncryptedURIKDFConfig
  ): Required<TEncryptedURIKDFConfig> {
    return EncryptedURIDecoder.getKDFConfig(kdfConfig, kdfDefaultConfig);
  }
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

  params?: TEncryptedURIParams<T>;
};

export type TEncryptedURIEncryptableDefaultParams<T extends TURIParams> = {
  content: string;
  password: string;
} & TEncryptedURIDefaultParams<T>;

export type TEncrypterClass<T extends TURIParams> = { new (resultset: TEncryptedURIResultset<T>, ...args: any[]): EncryptedURIEncrypter<any> } & { algorithm?: string };
export type TDecrypterClass<T extends TURIParams> = { new (decoded: TEncryptedURI<T>, password: string, kdf: Required<TEncryptedURIKDFConfig>, ...args: any[]): EncryptedURIDecrypter<T> };
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

  static readonly defaultConfigs: Required<TEncryptedURIKDFConfig> = {
    kdf: 'pbkdf2',
    hasher: 'sha256',
    ignoreDefaults: true,
    derivateKeyLength: 32,
    rounds: 32
  };

  static readonly defaultAlgotithm = 'aes';

  static readonly supportedAlgorithm: {
    [algorithm: string]: [
      TEncrypterClass<any>,
      TDecrypterClass<any>
    ]
  } = { };

  static getKDFConfig<T extends TURIParams>(
    decoded?: TEncryptedURI<T> | TEncryptedURIResultset<T>,
    defaultConfig?: TEncryptedURIKDFConfig
  ): Required<TEncryptedURIKDFConfig> {
    return EncryptedURIDecoder.getKDFConfig<T>(decoded, defaultConfig);
  }

  static castKDFConfigToParams(
    content: { kdf?: TEncryptedURIKDFConfig }
  ): TEncryptedURIParams<TURIParams> {
    return EncryptedURIEncoder.castKDFConfigToParams(content);    
  }

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

  static decrypt(
    uri: string,
    password: string,
    defaultKDFConfig?: TEncryptedURIKDFConfig,
    ...args: any[]
  ): Promise<string> {
    const uriDecoded = new EncryptedURIParser(uri).decoded;
    const [ , decryptor ] = this.getAlgorithm(uriDecoded.algorithm);
    const kdfConfigs: Required<TEncryptedURIKDFConfig> = {
      ...EncryptedURI.defaultConfigs, ...defaultKDFConfig
    };
    return new decryptor(uriDecoded, password, kdfConfigs, ...args).decrypt();
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
    algorithm = algorithm || EncryptedURI.defaultAlgotithm;
    const [ encryptor, decryptor ] = this.supportedAlgorithm[algorithm] || [ null, null];
    if (!encryptor && !decryptor) {
      throw new Error(`Algorithm '${algorithm}' not supported`);
    }

    return [ encryptor, decryptor ];
  }
}
