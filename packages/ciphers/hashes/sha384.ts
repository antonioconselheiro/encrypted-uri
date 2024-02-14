import { sha384 } from '@noble/hashes/sha512'
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha384', sha384);
