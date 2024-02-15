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

export type TEncryptedFullDefaultsConfig = {
  /**
   * If set as `true` and the choosen algorithm is aes/cbc,
   * the algorithm name will be not included.
   * 
   * If set as `false` the algorithm will be always included.
   * 
   * @default true
   */
  ignoreDefaultAlgorithm?: boolean;

  /**
   * If set as `true` and there is only one mandatory param include
   * in URI params, the attribute name will be not included, only
   * the value.
   *
   * If set as `false` the mandatory param name will be always included.
   *
   * @default true
   */
  ignoreMandatoryParamName?: boolean;

  /**
   * If set as `true` will not include params with default value set.
   *
   * If set as `false` will aways include all params, even if it is
   * a default value.
   *
   * @default true
   */
  ignoreDefaultValues?: boolean;
};

export type TEncryptedDefaultsConfig = {
  /**
   * The value set will be replicated in the following configs:
   *  `ignoreDefaultAlgorithm`, `ignoreMandatoryParamName` and
   * `ignoreDefaultValues`.
   *
   * @default true
   */
  ignoreDefaults: boolean;
} & TEncryptedFullDefaultsConfig;

export type TEncryptedURIKDFParams = {

  /**
   * Only pbkdf2 supported, just if someone see purpose in alternative KDF,
   * if you need this come to me, open an issue
   * 
   * @default pbkdf2
   */
  kdf?: 'pbkdf2',

  /**
   * Hashing algorithm supported by pbkdf2
   * 
   * @default sha256
   */
  hasher?: string | 'sha256' | 'sha512'| 'sha512_256'| 'sha384'| 'sha3_512'| 'sha3_384'| 'sha3_256'| 'sha3_224'| 'keccak_512'| 'keccak_384'| 'keccak_256'| 'keccak_224';

  /**
   * Iterations of hashing for pbkdf2
   * 
   * @default 32
   */
  rounds?: number;

  /**
   * Derivate key length for pbkdf2, fixed to 32 until I find a
   * way to customize this
   * 
   * @default 32
   */
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  derivateKeyLength?: 32;
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
    params: TEncryptedURIKDFParams,
    paramName: keyof TEncryptedURIKDFParams,
    config?: TEncryptedDefaultsConfig
  ): boolean {
    const paramWithDefaults: Required<TEncryptedURIKDFParams> = {
      ...EncryptedURI.defaultParams,
      ...params
    };

    const configWithDefaults = EncryptedURI.getConfigsOfDefaults(config);

    if (
      !paramWithDefaults[paramName] ||
      configWithDefaults.ignoreDefaultValues &&
      EncryptedURI.defaultParams[paramName] === paramWithDefaults[paramName]
      
    ) {
      return true; 
    }

    return false;
  }

  static castKDFConfigToParams(
    content: {
      kdf?: TEncryptedURIKDFParams,
      config?: TEncryptedDefaultsConfig
    }
  ): TEncryptedURIParams<TURIParams> {
    const params: TEncryptedURIParams<TURIParams> = {};

    if (content.kdf) {
      if (!this.propertyShouldBeIgnored(
        content.kdf, 'kdf', content.config
      )) {
        params.kdf = content.kdf.kdf;
      }

      if (!this.propertyShouldBeIgnored(
        content.kdf, 'hasher', content.config
      )) {
        params.h = content.kdf.hasher;
      }

      if (!this.propertyShouldBeIgnored(
        content.kdf, 'derivateKeyLength', content.config
      )) {
        params.dklen = String(content.kdf.derivateKeyLength);
      }

      if (!this.propertyShouldBeIgnored(
        content.kdf, 'rounds', content.config
      )) {
        params.c = String(content.kdf.rounds);
      }
    }

    return params;
  }

  encode(content: TEncryptedURI<T> & { kdf?: TEncryptedURIKDFParams }): string {
    const algorithm = this.encodeAlgorithm(content);
    const parameters = this.encodeParameters(content);

    if (parameters) {
      return `encrypted:${algorithm}?${parameters};${content.cipher}`;
    } else {
      return `encrypted:${algorithm};${content.cipher}`;
    }
  }

  private encodeParameters(
    content: TEncryptedURI<T> & {
      kdf?: TEncryptedURIKDFParams,
      config?: TEncryptedDefaultsConfig
    }
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

  constructor(content: string);
  constructor(content: TEncryptedURI<T> & {
    kdf?: TEncryptedURIKDFParams | undefined;
  });
  constructor(content: string | TEncryptedURI<T> & {
    kdf?: TEncryptedURIKDFParams | undefined;
  }) {
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
    protected params: TEncryptedURIResultset<T>
  ) { }
  
  abstract encrypt(): Promise<TEncryptedURI<T>>;
}

export abstract class EncryptedURIDecrypter<T extends TURIParams> {

  protected kdf: Required<TEncryptedURIKDFParams>;

  constructor(
    protected decoded: TEncryptedURI<T>,
    protected password: string
  ) {
    this.kdf = this.getKDFParams(this.decoded);
  }

  abstract decrypt(): Promise<string>;

  private getKDFParams(
    kdfConfig: TEncryptedURI<T>
  ): Required<TEncryptedURIKDFParams> {
    return EncryptedURI.getKDFParams(kdfConfig);
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
   * @default '32'
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
  kdf?: TEncryptedURIKDFParams;

  params?: TEncryptedURIParams<T>;
};

export type TEncryptedURIEncryptableDefaultParams<T extends TURIParams> = {
  content: string;
  password: string;
  config?: TEncryptedDefaultsConfig;
} & TEncryptedURIDefaultParams<T>;

export type TEncrypterClass<T extends TURIParams> = { new (resultset: TEncryptedURIResultset<T>, ...args: any[]): EncryptedURIEncrypter<any> } & { algorithm?: string };
export type TDecrypterClass<T extends TURIParams> = { new (decoded: TEncryptedURI<T>, password: string, kdf: Required<TEncryptedURIKDFParams>, ...args: any[]): EncryptedURIDecrypter<T> };
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

  static readonly defaultParams: Required<TEncryptedURIKDFParams> = {
    kdf: 'pbkdf2',
    hasher: 'sha256',
    derivateKeyLength: 32,
    rounds: 32
  };

  static readonly defaultAlgotithm = 'aes/cbc';

  static readonly supportedAlgorithm: {
    [algorithm: string]: [
      TEncrypterClass<any>,
      TDecrypterClass<any>
    ]
  } = { };

  static getConfigsOfDefaults(config?: TEncryptedDefaultsConfig): Required<TEncryptedFullDefaultsConfig> {
    const defaultConfigs: Required<TEncryptedFullDefaultsConfig> = {
      ignoreDefaultAlgorithm: true,
      ignoreDefaultValues: true,
      ignoreMandatoryParamName: true
    };

    if (!config) {
      return defaultConfigs;
    } else if ('ignoreDefaults' in config) {
      return {
        ignoreDefaultAlgorithm: config.ignoreDefaults,
        ignoreDefaultValues: config.ignoreDefaults,
        ignoreMandatoryParamName: config.ignoreDefaults
      };
    } else {
      return {
        ...defaultConfigs,
        ...(config as TEncryptedFullDefaultsConfig)
      };
    }
  }
  
  static getKDFParams<T extends TURIParams>(
    /**
     * if you're decoding pass TEncryptedURI<T>,
     * if you're encoding pass TEncryptedURIResultset<T>
     * 
     * @optional
     */
    kdfParams?: TEncryptedURI<T> | TEncryptedURIResultset<T>
  ): Required<TEncryptedURIKDFParams> {
    let params: TEncryptedURIKDFParams = EncryptedURI.defaultParams;
    if (kdfParams) {
      if ('kdf' in kdfParams && kdfParams.kdf) {
        params = kdfParams.kdf;
      } else if (kdfParams.params) {
        params = EncryptedURI.castParamsToConfig(kdfParams.params);
      }
    }
    
    const configWithDefaults: Required<TEncryptedURIKDFParams> = {
      ...EncryptedURI.defaultParams,
      ...params
    };
  
    return configWithDefaults;
  }

  private static castParamsToConfig<T extends TURIParams>(
    params?: TEncryptedURIParams<T>
  ): TEncryptedURIKDFParams {
    const config: TEncryptedURIKDFParams = {};
  
    if (!params) {
      return config;
    }
  
    if (params.kdf === 'string') {
      config.kdf = params.kdf as 'pbkdf2';
    }
  
    if (typeof params.h === 'string') {
      config.hasher = params.h;
    }
  
    if (typeof params.dklen === 'string') {
      const derivateKeyLength = Number(params.dklen);
      if (Number.isSafeInteger(derivateKeyLength)) {
        //  remove any quando issue for resolvido
        //  https://github.com/antonioconselheiro/encrypted-uri/issues/31
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        config.derivateKeyLength = derivateKeyLength as any;
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

  static castKDFConfigToParams(
    content: { kdf?: TEncryptedURIKDFParams }
  ): TEncryptedURIParams<TURIParams> {
    return EncryptedURIEncoder.castKDFConfigToParams(content);    
  }

  static matcher(uri: string): boolean {
    return new EncryptedURISyntaxMatcher().match(uri);
  }

  static encode<T extends TURIParams>(params: TEncryptedURI<T> & {
    kdf?: TEncryptedURIKDFParams | undefined;
  }): string {
    return new EncryptedURIParser(params).encoded;
  }

  static async encrypt<T extends TURIParams>(
    params: TEncryptedURIEncryptableDefaultParams<T>, ...args: any[]
  ): Promise<string> {
    const [ encrypter ] = this.getAlgorithm(params.algorithm);
    const ciphred = await new encrypter(params, ...args).encrypt();
    ciphred.algorithm = encrypter.algorithm || params.algorithm;

    return Promise.resolve(this.encode({ ...ciphred, kdf: params.kdf }));
  }

  static decrypt(
    uri: string,
    password: string,
    ...args: any[]
  ): Promise<string> {
    const uriDecoded = new EncryptedURIParser(uri).decoded;
    const [ , decryptor ] = this.getAlgorithm(uriDecoded.algorithm);
    const kdfConfigs: Required<TEncryptedURIKDFParams> = {
      ...EncryptedURI.defaultParams
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
