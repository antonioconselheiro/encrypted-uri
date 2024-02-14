import { CHash } from '@noble/hashes/utils';

export class HashSupport {
  private static readonly supported: {
    [name: string]: CHash
  } = {};

  static addSupport(name: string, hasher: CHash): void {
    if (!this.supported[name]) {
      this.supported[name] = hasher;
    } else {
      console.warn(`HashSupport: "${name}" hasher already loaded, not overriding`);
    }
  }

  static listSupported(): string[] {
    return Object.keys(this.supported);
  }

  static get(hasherName: string): CHash {
    const hasher = this.supported[hasherName];
    if (!hasher) {
      throw new Error(`"${hasherName}" not supported`);
    }

    return hasher;
  }
}
