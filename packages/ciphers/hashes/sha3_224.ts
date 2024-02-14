import { sha3_224 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha3_224', sha3_224);
