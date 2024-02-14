import { sha3_256 } from '@noble/hashes/sha3';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha3_256', sha3_256);
