import { CHash } from '@noble/hashes/utils';

export class HashSupport {
  private static readonly suportted: {
    [name: string]: CHash
  } = {};

  static addSupport(name: string, hasher: CHash) {
    this.suportted[name] = hasher;
  }

  static listSupported(): string[] {
    return Object.keys(this.suportted);
  }

  static get(hasherName: string): CHash {
    return this.suportted[hasherName];
  }
}
