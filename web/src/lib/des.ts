// DES（Data Encryption Standard，FIPS 46-3）从零实现。
// 结构：64-bit 分组、16 轮 Feistel、56-bit 有效密钥（8 字节含奇偶校验位，本实现忽略校验）。
// 对照向量（经典教材例）：key=133457799BBCDFF1，明文 0123456789ABCDEF → 密文 85E813540F0AB405。
// 与 Block/DES/main.py 同构；额外暴露 16 轮轨迹与“变异 S1”创新对照实验。

export const DES_BLOCK = 8;

// 初始置换 / 逆初始置换（1-based，从 MSB 数起）
const IP = [
  58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7,
];
const FP = [
  40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25,
];
// 扩展置换 E（32→48）、P 置换（32→32）
const E = [
  32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
  16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1,
];
const P = [
  16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25,
];
// 密钥调度：PC-1（64→56）、PC-2（56→48）、每轮左移位数
const PC1 = [
  57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
  59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,
  31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
  29,21,13,5,28,20,12,4,
];
const PC2 = [
  14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
  26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
  51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,
];
const SH = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

// 8 个 S-box（标准 DES S1~S8）
const S: number[][][] = [
  [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
  ],
  [
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
  ],
  [
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
  ],
  [
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
  ],
  [
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
  ],
  [
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
  ],
  [
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
  ],
  [
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
  ],
];

// ---------- 位运算工具（内部使用 BigInt 表示 64/56/48/32 bit 数值） ----------
const M32 = (1n << 32n) - 1n;
const M28 = (1n << 28n) - 1n;

function bytesToBigInt(b: Uint8Array): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}

function bigIntToBytes(x: bigint, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** 通用置换：table 元素为 1-based 的源比特位（从 inBits 的 MSB 数起）。 */
function permBig(x: bigint, table: number[], inBits: number): bigint {
  let out = 0n;
  for (let i = 0; i < table.length; i++) {
    const src = BigInt(inBits - table[i]);
    if ((x >> src) & 1n) out |= 1n << BigInt(table.length - 1 - i);
  }
  return out;
}

function rol28(v: bigint, s: number): bigint {
  const n = BigInt(s);
  return ((v << n) | (v >> (28n - n))) & M28;
}

const hexN = (x: bigint, bits: number) => x.toString(16).padStart(bits / 4, "0");

// ---------- 密钥调度 ----------
function subkeys(key: Uint8Array): bigint[] {
  const k56 = permBig(bytesToBigInt(key), PC1, 64);
  let c = k56 >> 28n;
  let d = k56 & M28;
  const out: bigint[] = [];
  for (const s of SH) {
    c = rol28(c, s);
    d = rol28(d, s);
    out.push(permBig((c << 28n) | d, PC2, 56));
  }
  return out;
}

// ---------- Feistel 轮函数 f(R, K) = P(S(E(R) ⊕ K)) ----------
function feistel(r: bigint, k: bigint, variantS1 = false): bigint {
  const e = permBig(r, E, 32) ^ k; // 48 bit
  let out = 0n;
  for (let i = 0; i < 8; i++) {
    const six = Number((e >> BigInt(42 - 6 * i)) & 0x3fn);
    const row = ((six >> 5) << 1) | (six & 1);
    const col = (six >> 1) & 15;
    let v = S[i][row][col];
    if (variantS1 && i === 0) v = (v + 1) & 15; // 变异 S1：循环 +1 的创新对照
    out = (out << 4n) | BigInt(v);
  }
  return permBig(out, P, 32);
}

export interface DesRoundLog {
  round: number;
  subkey: string; // K_i（48 bit hex）
  f: string; // f(R_{i-1}, K_i)
  lIn: string;
  rIn: string;
  lOut: string;
  rOut: string;
}

/** 单分组加/解密（decrypt=true 时逆序使用子密钥），返回密文与逐轮轨迹。 */
export function desBlockCrypt(
  block8: Uint8Array,
  key8: Uint8Array,
  decrypt = false,
  variantS1 = false
): { ct: Uint8Array; log: DesRoundLog[] } {
  const ks = subkeys(key8);
  if (decrypt) ks.reverse();
  const ip = permBig(bytesToBigInt(block8), IP, 64);
  let L = ip >> 32n;
  let R = ip & M32;
  const log: DesRoundLog[] = [];
  for (let i = 0; i < 16; i++) {
    const K = ks[i];
    const f = feistel(R, K, variantS1);
    const lPrev = L, rPrev = R;
    L = R;
    R = lPrev ^ f;
    log.push({
      round: i + 1,
      subkey: hexN(K, 48),
      f: hexN(f, 32),
      lIn: hexN(lPrev, 32),
      rIn: hexN(rPrev, 32),
      lOut: hexN(L, 32),
      rOut: hexN(R, 32),
    });
  }
  const pre = (R << 32n) | L; // 最后一轮不交换
  const ct64 = permBig(pre, FP, 64);
  return { ct: bigIntToBytes(ct64, 8), log };
}

// ---------- PKCS#7 填充（分组 8 字节） ----------
export function pkcs7Pad8(data: Uint8Array): Uint8Array {
  const n = 8 - (data.length % 8);
  const out = new Uint8Array(data.length + n);
  out.set(data);
  for (let i = data.length; i < out.length; i++) out[i] = n;
  return out;
}

export function pkcs7Unpad8(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % 8 !== 0) throw new Error("密文长度必须是 8 的倍数");
  const n = data[data.length - 1];
  if (n < 1 || n > 8) throw new Error("填充错误：密钥不正确或密文损坏");
  for (let i = data.length - n; i < data.length; i++) {
    if (data[i] !== n) throw new Error("填充错误：密钥不正确或密文损坏");
  }
  return data.slice(0, data.length - n);
}

/** 整段数据加密：ECB + PKCS#7 填充。variantS1=true 时使用“变异 S1”做对照实验。 */
export function desEncrypt(data: Uint8Array, key8: Uint8Array, variantS1 = false): Uint8Array {
  const padded = pkcs7Pad8(data);
  const out = new Uint8Array(padded.length);
  for (let i = 0; i < padded.length; i += 8) {
    out.set(desBlockCrypt(padded.slice(i, i + 8), key8, false, variantS1).ct, i);
  }
  return out;
}

export function desDecrypt(data: Uint8Array, key8: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % 8 !== 0) throw new Error("密文长度必须是 8 的倍数");
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 8) {
    out.set(desBlockCrypt(data.slice(i, i + 8), key8, true).ct, i);
  }
  return pkcs7Unpad8(out);
}
