import {
  EncryptedURI,
  EncryptedURIDecrypter,
  EncryptedURIEncrypter
} from "./chunk-OWVUHSNY.js";
import "./chunk-HSNDBVJ3.js";

// node_modules/@noble/ciphers/esm/utils.js
var u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
var u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
function isBytes(a) {
  return a instanceof Uint8Array || a != null && typeof a === "object" && a.constructor.name === "Uint8Array";
}
var createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
var isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
if (!isLE)
  throw new Error("Non little-endian hardware is not supported");
var hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  else if (isBytes(data))
    data = data.slice();
  else
    throw new Error(`expected Uint8Array, got ${typeof data}`);
  return data;
}
function ensureBytes(b, len) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (typeof len === "number") {
    if (b.length !== len)
      throw new Error(`Uint8Array length ${len} expected`);
  }
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
var wrapCipher = (params, c) => {
  Object.assign(c, params);
  return c;
};
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}

// node_modules/@noble/ciphers/esm/_assert.js
function isBytes2(a) {
  return a != null && typeof a === "object" && (a instanceof Uint8Array || a.constructor.name === "Uint8Array");
}
function bytes(b, ...lengths) {
  if (!isBytes2(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}
function exists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function output(out, instance) {
  bytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`);
  }
}

// node_modules/@noble/ciphers/esm/_polyval.js
var BLOCK_SIZE = 16;
var ZEROS16 = new Uint8Array(16);
var ZEROS32 = u32(ZEROS16);
var POLY = 225;
var mul2 = (s0, s1, s2, s3) => {
  const hiBit = s3 & 1;
  return {
    s3: s2 << 31 | s3 >>> 1,
    s2: s1 << 31 | s2 >>> 1,
    s1: s0 << 31 | s1 >>> 1,
    s0: s0 >>> 1 ^ POLY << 24 & -(hiBit & 1)
    // reduce % poly
  };
};
var swapLE = (n) => (n >>> 0 & 255) << 24 | (n >>> 8 & 255) << 16 | (n >>> 16 & 255) << 8 | n >>> 24 & 255 | 0;
function _toGHASHKey(k) {
  k.reverse();
  const hiBit = k[15] & 1;
  let carry = 0;
  for (let i = 0; i < k.length; i++) {
    const t = k[i];
    k[i] = t >>> 1 | carry;
    carry = (t & 1) << 7;
  }
  k[0] ^= -hiBit & 225;
  return k;
}
var estimateWindow = (bytes2) => {
  if (bytes2 > 64 * 1024)
    return 8;
  if (bytes2 > 1024)
    return 4;
  return 2;
};
var GHASH = class {
  // We select bits per window adaptively based on expectedLength
  constructor(key, expectedLength) {
    this.blockLen = BLOCK_SIZE;
    this.outputLen = BLOCK_SIZE;
    this.s0 = 0;
    this.s1 = 0;
    this.s2 = 0;
    this.s3 = 0;
    this.finished = false;
    key = toBytes(key);
    ensureBytes(key, 16);
    const kView = createView(key);
    let k0 = kView.getUint32(0, false);
    let k1 = kView.getUint32(4, false);
    let k2 = kView.getUint32(8, false);
    let k3 = kView.getUint32(12, false);
    const doubles = [];
    for (let i = 0; i < 128; i++) {
      doubles.push({ s0: swapLE(k0), s1: swapLE(k1), s2: swapLE(k2), s3: swapLE(k3) });
      ({ s0: k0, s1: k1, s2: k2, s3: k3 } = mul2(k0, k1, k2, k3));
    }
    const W = estimateWindow(expectedLength || 1024);
    if (![1, 2, 4, 8].includes(W))
      throw new Error(`ghash: wrong window size=${W}, should be 2, 4 or 8`);
    this.W = W;
    const bits = 128;
    const windows = bits / W;
    const windowSize = this.windowSize = 2 ** W;
    const items = [];
    for (let w = 0; w < windows; w++) {
      for (let byte = 0; byte < windowSize; byte++) {
        let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        for (let j = 0; j < W; j++) {
          const bit = byte >>> W - j - 1 & 1;
          if (!bit)
            continue;
          const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
          s0 ^= d0, s1 ^= d1, s2 ^= d2, s3 ^= d3;
        }
        items.push({ s0, s1, s2, s3 });
      }
    }
    this.t = items;
  }
  _updateBlock(s0, s1, s2, s3) {
    s0 ^= this.s0, s1 ^= this.s1, s2 ^= this.s2, s3 ^= this.s3;
    const { W, t, windowSize } = this;
    let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    const mask = (1 << W) - 1;
    let w = 0;
    for (const num of [s0, s1, s2, s3]) {
      for (let bytePos = 0; bytePos < 4; bytePos++) {
        const byte = num >>> 8 * bytePos & 255;
        for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
          const bit = byte >>> W * bitPos & mask;
          const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
          o0 ^= e0, o1 ^= e1, o2 ^= e2, o3 ^= e3;
          w += 1;
        }
      }
    }
    this.s0 = o0;
    this.s1 = o1;
    this.s2 = o2;
    this.s3 = o3;
  }
  update(data) {
    data = toBytes(data);
    exists(this);
    const b32 = u32(data);
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    const left = data.length % BLOCK_SIZE;
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(b32[i * 4 + 0], b32[i * 4 + 1], b32[i * 4 + 2], b32[i * 4 + 3]);
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      this._updateBlock(ZEROS32[0], ZEROS32[1], ZEROS32[2], ZEROS32[3]);
      ZEROS32.fill(0);
    }
    return this;
  }
  destroy() {
    const { t } = this;
    for (const elm of t) {
      elm.s0 = 0, elm.s1 = 0, elm.s2 = 0, elm.s3 = 0;
    }
  }
  digestInto(out) {
    exists(this);
    output(out, this);
    this.finished = true;
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(out);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    return out;
  }
  digest() {
    const res = new Uint8Array(BLOCK_SIZE);
    this.digestInto(res);
    this.destroy();
    return res;
  }
};
var Polyval = class extends GHASH {
  constructor(key, expectedLength) {
    key = toBytes(key);
    const ghKey = _toGHASHKey(key.slice());
    super(ghKey, expectedLength);
    ghKey.fill(0);
  }
  update(data) {
    data = toBytes(data);
    exists(this);
    const b32 = u32(data);
    const left = data.length % BLOCK_SIZE;
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(swapLE(b32[i * 4 + 3]), swapLE(b32[i * 4 + 2]), swapLE(b32[i * 4 + 1]), swapLE(b32[i * 4 + 0]));
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      this._updateBlock(swapLE(ZEROS32[3]), swapLE(ZEROS32[2]), swapLE(ZEROS32[1]), swapLE(ZEROS32[0]));
      ZEROS32.fill(0);
    }
    return this;
  }
  digestInto(out) {
    exists(this);
    output(out, this);
    this.finished = true;
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(out);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    return out.reverse();
  }
};
function wrapConstructorWithKey(hashCons) {
  const hashC = (msg, key) => hashCons(key, msg.length).update(toBytes(msg)).digest();
  const tmp = hashCons(new Uint8Array(16), 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (key, expectedLength) => hashCons(key, expectedLength);
  return hashC;
}
var ghash = wrapConstructorWithKey((key, expectedLength) => new GHASH(key, expectedLength));
var polyval = wrapConstructorWithKey((key, expectedLength) => new Polyval(key, expectedLength));

// node_modules/@noble/ciphers/esm/aes.js
var BLOCK_SIZE2 = 16;
var BLOCK_SIZE32 = 4;
var EMPTY_BLOCK = new Uint8Array(BLOCK_SIZE2);
var POLY2 = 283;
function mul22(n) {
  return n << 1 ^ POLY2 & -(n >> 7);
}
function mul(a, b) {
  let res = 0;
  for (; b > 0; b >>= 1) {
    res ^= a & -(b & 1);
    a = mul22(a);
  }
  return res;
}
var _sbox = (() => {
  let t = new Uint8Array(256);
  for (let i = 0, x = 1; i < 256; i++, x ^= mul22(x))
    t[i] = x;
  const sbox = new Uint8Array(256);
  sbox[0] = 99;
  for (let i = 0; i < 255; i++) {
    let x = t[255 - i];
    x |= x << 8;
    sbox[t[i]] = (x ^ x >> 4 ^ x >> 5 ^ x >> 6 ^ x >> 7 ^ 99) & 255;
  }
  return sbox;
})();
var _inv_sbox = _sbox.map((_, j) => _sbox.indexOf(j));
var rotr32_8 = (n) => n << 24 | n >>> 8;
var rotl32_8 = (n) => n << 8 | n >>> 24;
function genTtable(sbox, fn) {
  if (sbox.length !== 256)
    throw new Error("Wrong sbox length");
  const T0 = new Uint32Array(256).map((_, j) => fn(sbox[j]));
  const T1 = T0.map(rotl32_8);
  const T2 = T1.map(rotl32_8);
  const T3 = T2.map(rotl32_8);
  const T01 = new Uint32Array(256 * 256);
  const T23 = new Uint32Array(256 * 256);
  const sbox2 = new Uint16Array(256 * 256);
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const idx = i * 256 + j;
      T01[idx] = T0[i] ^ T1[j];
      T23[idx] = T2[i] ^ T3[j];
      sbox2[idx] = sbox[i] << 8 | sbox[j];
    }
  }
  return { sbox, sbox2, T0, T1, T2, T3, T01, T23 };
}
var TABLE_ENC = genTtable(_sbox, (s) => mul(s, 3) << 24 | s << 16 | s << 8 | mul(s, 2));
var TABLE_DEC = genTtable(_inv_sbox, (s) => mul(s, 11) << 24 | mul(s, 13) << 16 | mul(s, 9) << 8 | mul(s, 14));
var POWX = (() => {
  const p = new Uint8Array(16);
  for (let i = 0, x = 1; i < 16; i++, x = mul22(x))
    p[i] = x;
  return p;
})();
function expandKeyLE(key) {
  ensureBytes(key);
  const len = key.length;
  if (![16, 24, 32].includes(len))
    throw new Error(`aes: wrong key size: should be 16, 24 or 32, got: ${len}`);
  const { sbox2 } = TABLE_ENC;
  const k32 = u32(key);
  const Nk = k32.length;
  const subByte = (n) => applySbox(sbox2, n, n, n, n);
  const xk = new Uint32Array(len + 28);
  xk.set(k32);
  for (let i = Nk; i < xk.length; i++) {
    let t = xk[i - 1];
    if (i % Nk === 0)
      t = subByte(rotr32_8(t)) ^ POWX[i / Nk - 1];
    else if (Nk > 6 && i % Nk === 4)
      t = subByte(t);
    xk[i] = xk[i - Nk] ^ t;
  }
  return xk;
}
function expandKeyDecLE(key) {
  const encKey = expandKeyLE(key);
  const xk = encKey.slice();
  const Nk = encKey.length;
  const { sbox2 } = TABLE_ENC;
  const { T0, T1, T2, T3 } = TABLE_DEC;
  for (let i = 0; i < Nk; i += 4) {
    for (let j = 0; j < 4; j++)
      xk[i + j] = encKey[Nk - i - 4 + j];
  }
  encKey.fill(0);
  for (let i = 4; i < Nk - 4; i++) {
    const x = xk[i];
    const w = applySbox(sbox2, x, x, x, x);
    xk[i] = T0[w & 255] ^ T1[w >>> 8 & 255] ^ T2[w >>> 16 & 255] ^ T3[w >>> 24];
  }
  return xk;
}
function apply0123(T01, T23, s0, s1, s2, s3) {
  return T01[s0 << 8 & 65280 | s1 >>> 8 & 255] ^ T23[s2 >>> 8 & 65280 | s3 >>> 24 & 255];
}
function applySbox(sbox2, s0, s1, s2, s3) {
  return sbox2[s0 & 255 | s1 & 65280] | sbox2[s2 >>> 16 & 255 | s3 >>> 16 & 65280] << 16;
}
function encrypt(xk, s0, s1, s2, s3) {
  const { sbox2, T01, T23 } = TABLE_ENC;
  let k = 0;
  s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t02 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
    const t12 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
    const t22 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
    const t32 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
    s0 = t02, s1 = t12, s2 = t22, s3 = t32;
  }
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function decrypt(xk, s0, s1, s2, s3) {
  const { sbox2, T01, T23 } = TABLE_DEC;
  let k = 0;
  s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t02 = xk[k++] ^ apply0123(T01, T23, s0, s3, s2, s1);
    const t12 = xk[k++] ^ apply0123(T01, T23, s1, s0, s3, s2);
    const t22 = xk[k++] ^ apply0123(T01, T23, s2, s1, s0, s3);
    const t32 = xk[k++] ^ apply0123(T01, T23, s3, s2, s1, s0);
    s0 = t02, s1 = t12, s2 = t22, s3 = t32;
  }
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s3, s2, s1);
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s0, s3, s2);
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s1, s0, s3);
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s2, s1, s0);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function getDst(len, dst) {
  if (!dst)
    return new Uint8Array(len);
  ensureBytes(dst);
  if (dst.length < len)
    throw new Error(`aes: wrong destination length, expected at least ${len}, got: ${dst.length}`);
  return dst;
}
function ctrCounter(xk, nonce, src, dst) {
  ensureBytes(nonce, BLOCK_SIZE2);
  ensureBytes(src);
  const srcLen = src.length;
  dst = getDst(srcLen, dst);
  const ctr3 = nonce;
  const c32 = u32(ctr3);
  let { s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]);
  const src32 = u32(src);
  const dst32 = u32(dst);
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    dst32[i + 0] = src32[i + 0] ^ s0;
    dst32[i + 1] = src32[i + 1] ^ s1;
    dst32[i + 2] = src32[i + 2] ^ s2;
    dst32[i + 3] = src32[i + 3] ^ s3;
    let carry = 1;
    for (let i2 = ctr3.length - 1; i2 >= 0; i2--) {
      carry = carry + (ctr3[i2] & 255) | 0;
      ctr3[i2] = carry & 255;
      carry >>>= 8;
    }
    ({ s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]));
  }
  const start = BLOCK_SIZE2 * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    const buf = u8(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++)
      dst[i] = src[i] ^ buf[pos];
  }
  return dst;
}
function ctr32(xk, isLE2, nonce, src, dst) {
  ensureBytes(nonce, BLOCK_SIZE2);
  ensureBytes(src);
  dst = getDst(src.length, dst);
  const ctr3 = nonce;
  const c32 = u32(ctr3);
  const view = createView(ctr3);
  const src32 = u32(src);
  const dst32 = u32(dst);
  const ctrPos = isLE2 ? 0 : 12;
  const srcLen = src.length;
  let ctrNum = view.getUint32(ctrPos, isLE2);
  let { s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]);
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    dst32[i + 0] = src32[i + 0] ^ s0;
    dst32[i + 1] = src32[i + 1] ^ s1;
    dst32[i + 2] = src32[i + 2] ^ s2;
    dst32[i + 3] = src32[i + 3] ^ s3;
    ctrNum = ctrNum + 1 >>> 0;
    view.setUint32(ctrPos, ctrNum, isLE2);
    ({ s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]));
  }
  const start = BLOCK_SIZE2 * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    const buf = u8(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++)
      dst[i] = src[i] ^ buf[pos];
  }
  return dst;
}
var ctr = wrapCipher({ blockSize: 16, nonceLength: 16 }, function ctr2(key, nonce) {
  ensureBytes(key);
  ensureBytes(nonce, BLOCK_SIZE2);
  function processCtr(buf, dst) {
    const xk = expandKeyLE(key);
    const n = nonce.slice();
    const out = ctrCounter(xk, n, buf, dst);
    xk.fill(0);
    n.fill(0);
    return out;
  }
  return {
    encrypt: (plaintext, dst) => processCtr(plaintext, dst),
    decrypt: (ciphertext, dst) => processCtr(ciphertext, dst)
  };
});
function validateBlockDecrypt(data) {
  ensureBytes(data);
  if (data.length % BLOCK_SIZE2 !== 0) {
    throw new Error(`aes/(cbc-ecb).decrypt ciphertext should consist of blocks with size ${BLOCK_SIZE2}`);
  }
}
function validateBlockEncrypt(plaintext, pcks5, dst) {
  let outLen = plaintext.length;
  const remaining = outLen % BLOCK_SIZE2;
  if (!pcks5 && remaining !== 0)
    throw new Error("aec/(cbc-ecb): unpadded plaintext with disabled padding");
  const b = u32(plaintext);
  if (pcks5) {
    let left = BLOCK_SIZE2 - remaining;
    if (!left)
      left = BLOCK_SIZE2;
    outLen = outLen + left;
  }
  const out = getDst(outLen, dst);
  const o = u32(out);
  return { b, o, out };
}
function validatePCKS(data, pcks5) {
  if (!pcks5)
    return data;
  const len = data.length;
  if (!len)
    throw new Error(`aes/pcks5: empty ciphertext not allowed`);
  const lastByte = data[len - 1];
  if (lastByte <= 0 || lastByte > 16)
    throw new Error(`aes/pcks5: wrong padding byte: ${lastByte}`);
  const out = data.subarray(0, -lastByte);
  for (let i = 0; i < lastByte; i++)
    if (data[len - i - 1] !== lastByte)
      throw new Error(`aes/pcks5: wrong padding`);
  return out;
}
function padPCKS(left) {
  const tmp = new Uint8Array(16);
  const tmp32 = u32(tmp);
  tmp.set(left);
  const paddingByte = BLOCK_SIZE2 - left.length;
  for (let i = BLOCK_SIZE2 - paddingByte; i < BLOCK_SIZE2; i++)
    tmp[i] = paddingByte;
  return tmp32;
}
var ecb = wrapCipher({ blockSize: 16 }, function ecb2(key, opts = {}) {
  ensureBytes(key);
  const pcks5 = !opts.disablePadding;
  return {
    encrypt: (plaintext, dst) => {
      ensureBytes(plaintext);
      const { b, o, out: _out } = validateBlockEncrypt(plaintext, pcks5, dst);
      const xk = expandKeyLE(key);
      let i = 0;
      for (; i + 4 <= b.length; ) {
        const { s0, s1, s2, s3 } = encrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
        o[i++] = s0, o[i++] = s1, o[i++] = s2, o[i++] = s3;
      }
      if (pcks5) {
        const tmp32 = padPCKS(plaintext.subarray(i * 4));
        const { s0, s1, s2, s3 } = encrypt(xk, tmp32[0], tmp32[1], tmp32[2], tmp32[3]);
        o[i++] = s0, o[i++] = s1, o[i++] = s2, o[i++] = s3;
      }
      xk.fill(0);
      return _out;
    },
    decrypt: (ciphertext, dst) => {
      validateBlockDecrypt(ciphertext);
      const xk = expandKeyDecLE(key);
      const out = getDst(ciphertext.length, dst);
      const b = u32(ciphertext);
      const o = u32(out);
      for (let i = 0; i + 4 <= b.length; ) {
        const { s0, s1, s2, s3 } = decrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
        o[i++] = s0, o[i++] = s1, o[i++] = s2, o[i++] = s3;
      }
      xk.fill(0);
      return validatePCKS(out, pcks5);
    }
  };
});
var cbc = wrapCipher({ blockSize: 16, nonceLength: 16 }, function cbc2(key, iv, opts = {}) {
  ensureBytes(key);
  ensureBytes(iv, 16);
  const pcks5 = !opts.disablePadding;
  return {
    encrypt: (plaintext, dst) => {
      const xk = expandKeyLE(key);
      const { b, o, out: _out } = validateBlockEncrypt(plaintext, pcks5, dst);
      const n32 = u32(iv);
      let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
      let i = 0;
      for (; i + 4 <= b.length; ) {
        s0 ^= b[i + 0], s1 ^= b[i + 1], s2 ^= b[i + 2], s3 ^= b[i + 3];
        ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
        o[i++] = s0, o[i++] = s1, o[i++] = s2, o[i++] = s3;
      }
      if (pcks5) {
        const tmp32 = padPCKS(plaintext.subarray(i * 4));
        s0 ^= tmp32[0], s1 ^= tmp32[1], s2 ^= tmp32[2], s3 ^= tmp32[3];
        ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
        o[i++] = s0, o[i++] = s1, o[i++] = s2, o[i++] = s3;
      }
      xk.fill(0);
      return _out;
    },
    decrypt: (ciphertext, dst) => {
      validateBlockDecrypt(ciphertext);
      const xk = expandKeyDecLE(key);
      const n32 = u32(iv);
      const out = getDst(ciphertext.length, dst);
      const b = u32(ciphertext);
      const o = u32(out);
      let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
      for (let i = 0; i + 4 <= b.length; ) {
        const ps0 = s0, ps1 = s1, ps2 = s2, ps3 = s3;
        s0 = b[i + 0], s1 = b[i + 1], s2 = b[i + 2], s3 = b[i + 3];
        const { s0: o0, s1: o1, s2: o2, s3: o3 } = decrypt(xk, s0, s1, s2, s3);
        o[i++] = o0 ^ ps0, o[i++] = o1 ^ ps1, o[i++] = o2 ^ ps2, o[i++] = o3 ^ ps3;
      }
      xk.fill(0);
      return validatePCKS(out, pcks5);
    }
  };
});
function computeTag(fn, isLE2, key, data, AAD) {
  const h = fn.create(key, data.length + (AAD?.length || 0));
  if (AAD)
    h.update(AAD);
  h.update(data);
  const num = new Uint8Array(16);
  const view = createView(num);
  if (AAD)
    setBigUint64(view, 0, BigInt(AAD.length * 8), isLE2);
  setBigUint64(view, 8, BigInt(data.length * 8), isLE2);
  h.update(num);
  return h.digest();
}
var gcm = wrapCipher({ blockSize: 16, nonceLength: 12, tagLength: 16 }, function gcm2(key, nonce, AAD) {
  ensureBytes(nonce);
  if (nonce.length === 0)
    throw new Error("aes/gcm: empty nonce");
  const tagLength = 16;
  function _computeTag(authKey, tagMask, data) {
    const tag = computeTag(ghash, false, authKey, data, AAD);
    for (let i = 0; i < tagMask.length; i++)
      tag[i] ^= tagMask[i];
    return tag;
  }
  function deriveKeys() {
    const xk = expandKeyLE(key);
    const authKey = EMPTY_BLOCK.slice();
    const counter = EMPTY_BLOCK.slice();
    ctr32(xk, false, counter, counter, authKey);
    if (nonce.length === 12) {
      counter.set(nonce);
    } else {
      const nonceLen = EMPTY_BLOCK.slice();
      const view = createView(nonceLen);
      setBigUint64(view, 8, BigInt(nonce.length * 8), false);
      ghash.create(authKey).update(nonce).update(nonceLen).digestInto(counter);
    }
    const tagMask = ctr32(xk, false, counter, EMPTY_BLOCK);
    return { xk, authKey, counter, tagMask };
  }
  return {
    encrypt: (plaintext) => {
      ensureBytes(plaintext);
      const { xk, authKey, counter, tagMask } = deriveKeys();
      const out = new Uint8Array(plaintext.length + tagLength);
      ctr32(xk, false, counter, plaintext, out);
      const tag = _computeTag(authKey, tagMask, out.subarray(0, out.length - tagLength));
      out.set(tag, plaintext.length);
      xk.fill(0);
      return out;
    },
    decrypt: (ciphertext) => {
      ensureBytes(ciphertext);
      if (ciphertext.length < tagLength)
        throw new Error(`aes/gcm: ciphertext less than tagLen (${tagLength})`);
      const { xk, authKey, counter, tagMask } = deriveKeys();
      const data = ciphertext.subarray(0, -tagLength);
      const passedTag = ciphertext.subarray(-tagLength);
      const tag = _computeTag(authKey, tagMask, data);
      if (!equalBytes(tag, passedTag))
        throw new Error("aes/gcm: invalid ghash tag");
      const out = ctr32(xk, false, counter, data);
      authKey.fill(0);
      tagMask.fill(0);
      xk.fill(0);
      return out;
    }
  };
});
var limit = (name, min, max) => (value) => {
  if (!Number.isSafeInteger(value) || min > value || value > max)
    throw new Error(`${name}: invalid value=${value}, must be [${min}..${max}]`);
};
var siv = wrapCipher({ blockSize: 16, nonceLength: 12, tagLength: 16 }, function siv2(key, nonce, AAD) {
  const tagLength = 16;
  const AAD_LIMIT = limit("AAD", 0, 2 ** 36);
  const PLAIN_LIMIT = limit("plaintext", 0, 2 ** 36);
  const NONCE_LIMIT = limit("nonce", 12, 12);
  const CIPHER_LIMIT = limit("ciphertext", 16, 2 ** 36 + 16);
  ensureBytes(nonce);
  NONCE_LIMIT(nonce.length);
  if (AAD) {
    ensureBytes(AAD);
    AAD_LIMIT(AAD.length);
  }
  function deriveKeys() {
    const len = key.length;
    if (len !== 16 && len !== 24 && len !== 32)
      throw new Error(`key length must be 16, 24 or 32 bytes, got: ${len} bytes`);
    const xk = expandKeyLE(key);
    const encKey = new Uint8Array(len);
    const authKey = new Uint8Array(16);
    const n32 = u32(nonce);
    let s0 = 0, s1 = n32[0], s2 = n32[1], s3 = n32[2];
    let counter = 0;
    for (const derivedKey of [authKey, encKey].map(u32)) {
      const d32 = u32(derivedKey);
      for (let i = 0; i < d32.length; i += 2) {
        const { s0: o0, s1: o1 } = encrypt(xk, s0, s1, s2, s3);
        d32[i + 0] = o0;
        d32[i + 1] = o1;
        s0 = ++counter;
      }
    }
    xk.fill(0);
    return { authKey, encKey: expandKeyLE(encKey) };
  }
  function _computeTag(encKey, authKey, data) {
    const tag = computeTag(polyval, true, authKey, data, AAD);
    for (let i = 0; i < 12; i++)
      tag[i] ^= nonce[i];
    tag[15] &= 127;
    const t32 = u32(tag);
    let s0 = t32[0], s1 = t32[1], s2 = t32[2], s3 = t32[3];
    ({ s0, s1, s2, s3 } = encrypt(encKey, s0, s1, s2, s3));
    t32[0] = s0, t32[1] = s1, t32[2] = s2, t32[3] = s3;
    return tag;
  }
  function processSiv(encKey, tag, input) {
    let block = tag.slice();
    block[15] |= 128;
    return ctr32(encKey, true, block, input);
  }
  return {
    encrypt: (plaintext) => {
      ensureBytes(plaintext);
      PLAIN_LIMIT(plaintext.length);
      const { encKey, authKey } = deriveKeys();
      const tag = _computeTag(encKey, authKey, plaintext);
      const out = new Uint8Array(plaintext.length + tagLength);
      out.set(tag, plaintext.length);
      out.set(processSiv(encKey, tag, plaintext));
      encKey.fill(0);
      authKey.fill(0);
      return out;
    },
    decrypt: (ciphertext) => {
      ensureBytes(ciphertext);
      CIPHER_LIMIT(ciphertext.length);
      const tag = ciphertext.subarray(-tagLength);
      const { encKey, authKey } = deriveKeys();
      const plaintext = processSiv(encKey, tag, ciphertext.subarray(0, -tagLength));
      const expectedTag = _computeTag(encKey, authKey, plaintext);
      encKey.fill(0);
      authKey.fill(0);
      if (!equalBytes(tag, expectedTag))
        throw new Error("invalid polyval tag");
      return plaintext;
    }
  };
});

// node_modules/@encrypted-uri/ciphers/index.js
function getInitializationVector(encryptedUriDecoded) {
  return encryptedUriDecoded?.params?.iv || encryptedUriDecoded?.queryString || "";
}
function getNumberOnce(encryptedUriDecoded) {
  return encryptedUriDecoded?.params?.no || encryptedUriDecoded?.queryString || "";
}
var EncryptedURIAESCBCEncrypter = class extends EncryptedURIEncrypter {
  constructor(params) {
    super(params);
    this.params = params;
  }
  encrypt() {
    const key = utf8ToBytes(this.params.key);
    const iv = getInitializationVector(this.params);
    const content = utf8ToBytes(this.params.content);
    return {
      algorithm: "aes/cbc",
      cypher: cbc(key, utf8ToBytes(iv)).encrypt(content).toString(),
      params: { iv }
    };
  }
};
var EncryptedURIAESCBCDecrypter = class extends EncryptedURIDecrypter {
  constructor(decoded, key) {
    super(decoded);
    this.key = key;
  }
  decrypt() {
    const key = utf8ToBytes(this.key);
    const iv = utf8ToBytes(getInitializationVector(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher);
    return cbc(key, iv).decrypt(cypher).toString();
  }
};
var EncryptedURIAESCTREncrypter = class extends EncryptedURIEncrypter {
  constructor(params) {
    super(params);
    this.params = params;
  }
  encrypt() {
    const key = utf8ToBytes(this.params.key);
    const iv = getInitializationVector(this.params);
    const content = utf8ToBytes(this.params.content);
    return {
      algorithm: "aes/ctr",
      cypher: ctr(key, utf8ToBytes(iv)).encrypt(content).toString(),
      params: { iv }
    };
  }
};
var EncryptedURIAESCTRDecrypter = class extends EncryptedURIDecrypter {
  constructor(decoded, key) {
    super(decoded);
    this.key = key;
  }
  decrypt() {
    const key = utf8ToBytes(this.key);
    const iv = utf8ToBytes(getInitializationVector(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher || "");
    return ctr(key, iv).decrypt(cypher).toString();
  }
};
var EncryptedURIAESECBEncrypter = class extends EncryptedURIEncrypter {
  constructor(params) {
    super(params);
    this.params = params;
  }
  encrypt() {
    const key = utf8ToBytes(this.params.key);
    const content = utf8ToBytes(this.params.content);
    return {
      algorithm: "aes/ecb",
      cypher: ecb(key).encrypt(content).toString()
    };
  }
};
var EncryptedURIAESECBDecrypter = class extends EncryptedURIDecrypter {
  constructor(decoded, key) {
    super(decoded);
    this.key = key;
  }
  decrypt() {
    const key = utf8ToBytes(this.key);
    const cypher = utf8ToBytes(this.decoded.cypher || "");
    return ecb(key).decrypt(cypher).toString();
  }
};
var EncryptedURIAESGCMEncrypter = class extends EncryptedURIEncrypter {
  constructor(params) {
    super(params);
    this.params = params;
  }
  encrypt() {
    const key = utf8ToBytes(this.params.key);
    const nonce = getNumberOnce(this.params);
    const content = utf8ToBytes(this.params.content);
    return {
      algorithm: "aes/gcm",
      cypher: gcm(key, utf8ToBytes(nonce)).encrypt(content).toString(),
      params: { no: nonce }
    };
  }
};
var EncryptedURIAESSIVDecrypter = class extends EncryptedURIDecrypter {
  constructor(decoded, key) {
    super(decoded);
    this.key = key;
  }
  decrypt() {
    const key = utf8ToBytes(this.key);
    const nonce = utf8ToBytes(getNumberOnce(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher);
    return siv(key, nonce).decrypt(cypher).toString();
  }
};
var EncryptedURIAESSIVEncrypter = class extends EncryptedURIEncrypter {
  constructor(params) {
    super(params);
    this.params = params;
  }
  encrypt() {
    const key = utf8ToBytes(this.params.key);
    const nonce = getNumberOnce(this.params);
    const content = utf8ToBytes(this.params.content);
    return {
      algorithm: "aes/gcm",
      cypher: siv(key, utf8ToBytes(nonce)).encrypt(content).toString(),
      params: { no: nonce }
    };
  }
};
var EncryptedURIAESGCMDecrypter = class extends EncryptedURIDecrypter {
  constructor(decoded, key) {
    super(decoded);
    this.key = key;
  }
  decrypt() {
    const key = utf8ToBytes(this.key);
    const nonce = utf8ToBytes(getNumberOnce(this.decoded));
    const cypher = utf8ToBytes(this.decoded.cypher);
    return gcm(key, nonce).decrypt(cypher).toString();
  }
};
function supportAES() {
  EncryptedURI.setAlgorithm("", EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm("aes", EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm("aes/cbc", EncryptedURIAESCBCEncrypter, EncryptedURIAESCBCDecrypter);
  EncryptedURI.setAlgorithm("aes/ebc", EncryptedURIAESECBEncrypter, EncryptedURIAESECBDecrypter);
  EncryptedURI.setAlgorithm("aes/ctr", EncryptedURIAESCTREncrypter, EncryptedURIAESCTRDecrypter);
  EncryptedURI.setAlgorithm("aes/gcm", EncryptedURIAESGCMEncrypter, EncryptedURIAESGCMDecrypter);
  EncryptedURI.setAlgorithm("aes/siv", EncryptedURIAESSIVEncrypter, EncryptedURIAESSIVDecrypter);
}
export {
  supportAES
};
/*! Bundled license information:

@noble/ciphers/esm/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/
//# sourceMappingURL=@encrypted-uri_ciphers.js.map
