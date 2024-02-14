import { keccak_256 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('keccak_256', keccak_256);
