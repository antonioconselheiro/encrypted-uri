import { sha256 } from '@noble/hashes/sha256';
import { HashSupport } from './hash-support';

HashSupport.addSupport('sha256', sha256);
