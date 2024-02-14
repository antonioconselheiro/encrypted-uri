import { sha3_512 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha3_512', sha3_512);
