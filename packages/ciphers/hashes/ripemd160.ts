import { ripemd160 } from '@noble/hashes/ripemd160';
import { HashSupport } from './hash-support';

HashSupport.addSupport('ripemd160', ripemd160);
