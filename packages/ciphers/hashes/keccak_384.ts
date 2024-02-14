import { keccak_384 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('keccak_384', keccak_384);

