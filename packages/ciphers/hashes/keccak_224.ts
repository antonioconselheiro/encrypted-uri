import { keccak_224 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('keccak_224', keccak_224);
