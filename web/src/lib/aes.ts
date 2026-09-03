// AES-128（FIPS 197）从零实现：16 字节分组、10 轮、ECB + PKCS#7。
// 状态按“列优先”存储（state[4*col + row]），与 Block/AES/main.py 保持一致。
// 对照向量（FIPS-197 附录 C.1）：key=000102030405060708090a0b0c0d0e0f，
// 明文 00112233445566778899aabbccddeeff → 密文 69c4e0d86a7b0430d8cdb78070b4c55a。

import { bitDiff } from "./bytes";

export const AES_BLOCK = 16;

// 字节代换表 S-box（GF(2^8) 乘法逆元 + 仿射变换，预计算）
const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);
const INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

const RCON = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

function xtime(x: number): number {
  return ((x << 1) ^ (x & 0x80 ? 0x11b : 0)) & 0xff;
}

/** GF(2^8) 乘法（x8 + x4 + x3 + x + 1） */
function gm(a: number, b: number): number {
  let r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return r;
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** 密钥扩展：128-bit 密钥 → 11 个轮密钥（每轮 16 字节） */
export function aesExpandKey(key: Uint8Array): Uint8Array[] {
  if (key.length !== 16) throw new Error("AES-128 密钥必须是 16 字节（32 位 hex 或 16 字符文本）");
  const w: number[][] = [];
  for (let i = 0; i < 16; i += 4) w.push([key[i], key[i + 1], key[i + 2], key[i + 3]]);
  for (let i = 4; i < 44; i++) {
    const t = w[i - 1].slice();
    if (i % 4 === 0) {
      const first = t.shift()!; // RotWord
      t.push(first);
      for (let j = 0; j < 4; j++) t[j] = SBOX[t[j]]; // SubWord
      t[0] ^= RCON[i / 4]; // 轮常数
    }
    w.push([w[i - 4][0] ^ t[0], w[i - 4][1] ^ t[1], w[i - 4][2] ^ t[2], w[i - 4][3] ^ t[3]]);
  }
  const rks: Uint8Array[] = [];
  for (let r = 0; r < 11; r++) rks.push(Uint8Array.from(w.slice(4 * r, 4 * r + 4).flat()));
  return rks;
}

function subBytes(s: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = SBOX[s[i]];
  return out;
}
function invSubBytes(s: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = INV_SBOX[s[i]];
  return out;
}
// ShiftRows：第 r 行循环左移 r 个字节（state 列优先存储）
function shiftRows(s: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  let k = 0;
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[k++] = s[4 * ((c + r) % 4) + r];
  return out;
}
function invShiftRows(s: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  let k = 0;
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++) out[k++] = s[4 * (((c - r) % 4 + 4) % 4) + r];
  return out;
}
// MixColumns：每列视为 GF(2^8) 多项式，乘以固定矩阵（2,3,1,1）
function mixColumns(s: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
    out[4 * c] = gm(a0, 2) ^ gm(a1, 3) ^ a2 ^ a3;
    out[4 * c + 1] = a0 ^ gm(a1, 2) ^ gm(a2, 3) ^ a3;
    out[4 * c + 2] = a0 ^ a1 ^ gm(a2, 2) ^ gm(a3, 3);
    out[4 * c + 3] = gm(a0, 3) ^ a1 ^ a2 ^ gm(a3, 2);
  }
  return out;
}
function invMixColumns(s: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
    out[4 * c] = gm(a0, 14) ^ gm(a1, 11) ^ gm(a2, 13) ^ gm(a3, 9);
    out[4 * c + 1] = gm(a0, 9) ^ gm(a1, 14) ^ gm(a2, 11) ^ gm(a3, 13);
    out[4 * c + 2] = gm(a0, 13) ^ gm(a1, 9) ^ gm(a2, 14) ^ gm(a3, 11);
    out[4 * c + 3] = gm(a0, 11) ^ gm(a1, 13) ^ gm(a2, 9) ^ gm(a3, 14);
  }
  return out;
}

/**
 * 单分组加密。trace=true 时返回 states[11]：
 * states[0] = 初始 AddRoundKey 之后，states[i] = 第 i 轮（Sub→Shift→[Mix]→ARK）之后。
 */
export function aesEncryptBlock(
  p16: Uint8Array,
  key: Uint8Array,
  trace = false
): { ct: Uint8Array; states: Uint8Array[] } {
  if (p16.length !== 16) throw new Error("AES 分组必须是 16 字节");
  const rks = aesExpandKey(key);
  let s = xorBytes(p16, rks[0]);
  const states: Uint8Array[] = [s.slice()];
  for (let r = 1; r <= 10; r++) {
    let x = subBytes(s);
    x = shiftRows(x);
    if (r < 10) x = mixColumns(x);
    s = xorBytes(x, rks[r]);
    states.push(s.slice());
  }
  return { ct: s, states };
}

export function aesDecryptBlock(c16: Uint8Array, key: Uint8Array): Uint8Array {
  if (c16.length !== 16) throw new Error("AES 分组必须是 16 字节");
  const rks = aesExpandKey(key);
  let s = xorBytes(c16, rks[10]);
  for (let r = 9; r >= 1; r--) {
    s = invShiftRows(invSubBytes(s));
    s = invMixColumns(xorBytes(s, rks[r]));
  }
  return xorBytes(invSubBytes(invShiftRows(s)), rks[0]);
}

// ---------- PKCS#7 填充（分组 16 字节） ----------
export function pkcs7Pad16(data: Uint8Array): Uint8Array {
  const n = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + n);
  out.set(data);
  for (let i = data.length; i < out.length; i++) out[i] = n;
  return out;
}
function pkcs7Unpad16(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % 16 !== 0) throw new Error("密文长度必须是 16 的倍数");
  const n = data[data.length - 1];
  if (n < 1 || n > 16) throw new Error("填充校验失败：密钥或密文可能错误");
  for (let i = data.length - n; i < data.length; i++) {
    if (data[i] !== n) throw new Error("填充校验失败：密钥或密文可能错误");
  }
  return data.slice(0, data.length - n);
}

/** 整段数据加密：ECB + PKCS#7。 */
export function aesEncrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  const padded = pkcs7Pad16(data);
  const out = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += 16) {
    out.set(aesEncryptBlock(padded.slice(i, i + 16), key).ct, i);
  }
  return out;
}

export function aesDecrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % 16 !== 0) throw new Error("密文长度必须是 16 的倍数");
  const raw = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) {
    raw.set(aesDecryptBlock(data.slice(i, i + 16), key), i);
  }
  return pkcs7Unpad16(raw);
}

/** 逐轮状态轨迹（页面“扩散过程”可视化）：返回 11 个状态。 */
export function aesRoundStates(p16: Uint8Array, key: Uint8Array): Uint8Array[] {
  return aesEncryptBlock(p16, key, true).states;
}

/** 雪崩实验：两个单分组明文（取各自前 16 字节）加密，统计 11 个状态逐轮差异比特。 */
export function aesAvalanche(
  p1: Uint8Array,
  p2: Uint8Array,
  key: Uint8Array
): { ctA: Uint8Array; ctB: Uint8Array; changes: number[] } {
  const a = aesEncryptBlock(p1, key, true);
  const b = aesEncryptBlock(p2, key, true);
  const changes = a.states.map((s, i) => bitDiff(s, b.states[i]));
  return { ctA: a.ct, ctB: b.ct, changes };
}
