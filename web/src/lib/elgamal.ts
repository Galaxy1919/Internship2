// ElGamal 公钥密码 (从零实现, BigInt)
// 对齐 Python publicKey/Elgamal/main.py:
//   - 安全素数 p = 2q + 1 (q 亦素数), 生成元 g 的阶为 q
//   - 加密: c1 = g^k, c2 = m·y^k (mod p)
//   - 解密: m = c2 · c1^{p-1-x} (费马小定理避免求逆)
//   - 签名: r = g^k, s = (H(m) - x·r)·k^{-1} mod (p-1)
//   - 验证: g^{H(m)} ≡ y^r · r^s (mod p)
//   - k 重用攻击: 在模 q = (p-1)/2 下解线性同余 k(s1-s2) ≡ (h1-h2) (mod q),
//     筛掉 g^k != r1 的伪解, 恢复 x 后用 g^x == y 回验 (2026-09 重构)

import { sha256 } from "./sha256";

// ---------------------------------------------------------------------------
// 基础数论
// ---------------------------------------------------------------------------

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod <= 1n) throw new Error("模数必须大于 1");
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

// 扩展欧几里得: 返回 (g, u, v) 使 a·u + b·v = g = gcd(a,b)
function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

export function modInv(a: bigint, m: bigint): bigint {
  const [g, s] = egcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error(`${a} 在模 ${m} 下无逆`);
  return ((s % m) + m) % m;
}

// 解 a·k ≡ b (mod n), 返回模 n 意义下全部解
export function solveLinearCongruence(a: bigint, b: bigint, n: bigint): bigint[] {
  const [g, u] = egcd(((a % n) + n) % n, n);
  const bb = ((b % n) + n) % n;
  if (bb % g !== 0n) return [];
  const m = n / g;
  let k0 = (((bb / g) % m) * ((u % m) + m) % m) % m;
  k0 = ((k0 % m) + m) % m;
  const out: bigint[] = [];
  for (let t = 0n; t < g; t++) out.push(k0 + t * m);
  return out;
}

// ---------------------------------------------------------------------------
// 素数与密钥生成
// ---------------------------------------------------------------------------

const FIRST_PRIMES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n];

export function isProbablePrime(n: bigint, rounds = 16): boolean {
  if (n < 2n) return false;
  for (const p of FIRST_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1n;
  }
  // 确定性底数对 < 3.3e24 足够; 这里取前 rounds 个素数 + 递增兜底
  const bases = FIRST_PRIMES.slice(0, Math.min(rounds, FIRST_PRIMES.length));
  for (let i = 0; i < bases.length; i++) {
    const a = ((bases[i] % (n - 1n)) + 2n) % (n - 1n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let j = 0n; j < r - 1n; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

function randBelow(n: bigint): bigint {
  const bytes = Math.ceil(n.toString(2).length / 8) + 1;
  const buf = new Uint8Array(bytes);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  let v = 0n;
  for (let i = 0; i < bytes; i++) v = (v << 8n) | BigInt(buf[i]);
  return v % n;
}

// 在 [2, n-1] 内随机取一个整数 (n 通常为子群阶 q)
export function randInRange(n: bigint): bigint {
  if (n <= 3n) return 2n;
  return 2n + randBelow(n - 2n);
}

// 生成安全素数对 p = 2q + 1
export function genSafePrime(bits: number): { p: bigint; q: bigint } {
  const qBits = bits - 1;
  for (;;) {
    let q = randBelow(1n << BigInt(qBits)) | (1n << BigInt(qBits - 1)) | 1n;
    if (!isProbablePrime(q)) continue;
    const p = 2n * q + 1n;
    if (isProbablePrime(p)) return { p, q };
  }
}

// 找 Zp* 中阶为 q 的元素: p = 2q+1 时取 g = h^2 (h 随机), 非 1 则阶为 q
export function findGenerator(p: bigint, q: bigint): bigint {
  for (;;) {
    const h = 2n + randBelow(p - 3n);
    const g = modPow(h, 2n, p);
    if (g !== 1n) return g;
  }
}

export interface ElGamalKey {
  p: bigint;
  q: bigint;
  g: bigint;
  x: bigint;
  y: bigint;
}

export function generateKey(bits = 128): ElGamalKey {
  const { p, q } = genSafePrime(bits);
  const g = findGenerator(p, q);
  const x = 2n + randBelow(q - 3n);
  const y = modPow(g, x, p);
  return { p, q, g, x, y };
}

// 供课堂演示: 从固定 p/q/g 生成密钥 (x 随机)
export function keyFromParams(p: bigint, q: bigint, g: bigint): ElGamalKey {
  if (p !== 2n * q + 1n) throw new Error("参数不满足 p = 2q + 1");
  if (g <= 1n || g >= p) throw new Error("生成元越界");
  const x = 2n + randBelow(q - 3n);
  const y = modPow(g, x, p);
  return { p, q, g, x, y };
}

// ---------------------------------------------------------------------------
// 哈希到整数: H(m) = SHA-256(msg) as bigint mod p
// ---------------------------------------------------------------------------

export function hashToInt(msg: string, p: bigint): bigint {
  const bytes = new TextEncoder().encode(msg);
  const digest = sha256(bytes);
  let v = 0n;
  for (const b of digest) v = (v << 8n) | BigInt(b);
  return v % p;
}

// ---------------------------------------------------------------------------
// 加解密
// ---------------------------------------------------------------------------

export function encrypt(
  m: bigint,
  pub: { p: bigint; g: bigint; y: bigint },
  k?: bigint,
): { c1: bigint; c2: bigint; k: bigint } {
  const { p, g, y } = pub;
  if (!(m >= 1n && m < p)) {
    throw new Error(`明文 m 必须 1 ≤ m < p, 当前 m=${m}, p bits=${p.toString(2).length}`);
  }
  let kk = k;
  if (kk === undefined) kk = 2n + randBelow(p - 3n);
  const c1 = modPow(g, kk, p);
  const c2 = (m * modPow(y, kk, p)) % p;
  return { c1, c2, k: kk };
}

export function decrypt(
  c1: bigint,
  c2: bigint,
  key: ElGamalKey,
): bigint {
  // c1^{-x} ≡ c1^{p-1-x} (费马小定理)
  const inv = modPow(c1, key.p - 1n - key.x, key.p);
  return (c2 * inv) % key.p;
}

// ---------------------------------------------------------------------------
// 签名与验证
// ---------------------------------------------------------------------------

export function sign(
  msg: string,
  key: ElGamalKey,
  k?: bigint,
): { r: bigint; s: bigint; h: bigint; k: bigint } {
  const p = key.p;
  let kk = k;
  for (;;) {
    if (kk === undefined) kk = 2n + randBelow(p - 3n);
    if (gcd(kk, p - 1n) !== 1n) {
      if (k !== undefined) throw new Error("指定的 k 与 p-1 不互素, 不能用于签名");
      kk = undefined;
      continue;
    }
    const r = modPow(key.g, kk, p);
    const h = hashToInt(msg, p);
    const s = (modInv(kk, p - 1n) * (((h - key.x * r) % (p - 1n)) + p - 1n)) % (p - 1n);
    if (s === 0n) {
      if (k !== undefined) throw new Error("指定的 k 导致 s=0, 请换一个 k");
      kk = undefined;
      continue;
    }
    return { r, s, h, k: kk };
  }
}

export function verify(
  msg: string,
  sig: { r: bigint; s: bigint },
  pub: { p: bigint; g: bigint; y: bigint },
): boolean {
  const { p, g, y } = pub;
  const { r, s } = sig;
  if (!(r > 0n && r < p && s > 0n && s < p - 1n)) return false;
  const h = hashToInt(msg, p);
  const lhs = modPow(g, h, p);
  const rhs = (modPow(y, r, p) * modPow(r, s, p)) % p;
  return lhs === rhs;
}

// ---------------------------------------------------------------------------
// 创新点: k 重用攻击 (2026-09 重构版, 与 Python 同步)
//   两次签名复用同一 k => r 相同。攻击方程 k(s1-s2) ≡ (h1-h2) 必须在模 q 下解,
//   模 p-1 下会因 2 因子引入伪解。恢复 x 后再以 g^x == y 回验。
// ---------------------------------------------------------------------------

export interface AttackResult {
  x: bigint;
  k: bigint;
  h1: bigint;
  h2: bigint;
  n: bigint; // q = (p-1)/2
  candidates: bigint[]; // 模 q 下的全部候选 k
  verified: boolean; // g^x == y
}

export function recoverXFromReusedK(
  msg1: string,
  sig1: { r: bigint; s: bigint },
  msg2: string,
  sig2: { r: bigint; s: bigint },
  pub: { p: bigint; g: bigint; y: bigint },
): AttackResult {
  const { p, g, y } = pub;
  const { r: r1, s: s1 } = sig1;
  const { r: r2, s: s2 } = sig2;
  if (r1 !== r2) throw new Error("两次签名的 r 不同, 说明 k 未复用; 此攻击不适用");
  // 安全素数 p = 2q + 1, g 的阶为 q; 攻击方程取模 q 才有唯一意义
  const n = (p - 1n) / 2n;
  const h1 = hashToInt(msg1, p);
  const h2 = hashToInt(msg2, p);
  const candidates = solveLinearCongruence(((s1 - s2) % n + n) % n, ((h1 - h2) % n + n) % n, n);
  for (const k of candidates) {
    if (k <= 0n || modPow(g, k, p) !== r1) continue;
    let x: bigint;
    try {
      x = ((((h1 - k * s1) % n) + n) % n * modInv(((r1 % n) + n) % n, n)) % n;
    } catch {
      continue;
    }
    if (x > 0n && x < n && modPow(g, x, p) === y) {
      return { x, k, h1, h2, n, candidates, verified: true };
    }
  }
  throw new Error("k 重用攻击恢复失败: 未找到合法私钥");
}
