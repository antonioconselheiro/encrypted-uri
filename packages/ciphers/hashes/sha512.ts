import { sha512 } from '@noble/hashes/sha512';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha512', sha512);
