type TEncryptedURIResultset = {
  algorithm: 'aes';
  mode: 'cbc' | 'ecb' | 'ctr' | 'gcm' | 'siv';
  initializationVector: string;
  padding: 'pkcs7' | 'ansix923' | 'iso10126' | 'iso97971' | 'zeropad' | 'nopad';
} | {
  algorithm: 'salsa20' | 'chacha' | 'xsalsa20' | 'xchacha' | 'poly1305' | 'chacha8' | 'chacha12';
  nonce: string;
};

type TURIEncryptedConfig = {
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
})
//implements TEncryptedURIResultset
class URIEncrypted  {

  static readonly INCLUDE_DEFAULTS = true;
  
  static readonly DEFAULT_ALGORITHM = 'aes';
  static readonly DEFAULT_AES_MODE = 'cbc';
  static readonly DEFAULT_AES_PADDING = 'pkcs7';

  readonly encoded: string;

  constructor(content: TEncryptedURIResultset, config?: TURIEncryptedConfig);
  constructor(content: string);
  constructor(
    content: string | TEncryptedURIResultset,
    config?: TURIEncryptedConfig
  ) {
    if (typeof content === 'string') {
      this.decode(this.encoded = content);
    } else {
      this.encoded = this.encode(content, config);
    }
  }

  private decode(content: string): void {

  }

  private encode(content: TEncryptedURIResultset, config?: TURIEncryptedConfig): string {
    const {
      alwaysIncludeAlgorithm,
      alwaysIncludeMode,
      alwaysIncludePadding,
      alwaysIncludeDefaultArgumentName
    } = this.normalizeConfig(config);

    let uriAlgorithm: string;
    if (alwaysIncludeAlgorithm) {
      uriAlgorithm = content.algorithm;

    }
  }

  private normalizeConfig(config?: TURIEncryptedConfig): {
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

class InvalidEncryptedArgument extends Error {

}
