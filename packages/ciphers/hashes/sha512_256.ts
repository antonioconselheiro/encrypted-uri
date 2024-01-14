import { sha512_256 } from '@noble/hashes/sha512';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha512_256', sha512_256);
