import { keccak_512 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('keccak_512', keccak_512);

