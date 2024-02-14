import { sha3_384 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha3_384', sha3_384);
