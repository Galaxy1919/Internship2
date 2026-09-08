// RSA 公钥密码从零实现 (BigInt)
// 对齐 Python publicKey/RSA/main.py:
//   - Miller-Rabin 概率素性检测 (可输出每轮见证 trace)
//   - 密钥生成: n = pq, phi = (p-1)(q-1), d = e^{-1} mod phi
//   - 裸 RSA 加解密 + CRT 加速解密 (dp/dq/qinv)
//   - 裸 RSA 签名 (SHA-256 截断) / 验证
//   - 创新点: e=3 小明文 立方根攻击 (integer cube root 牛顿迭代)
// 教材固定向量: p=61 q=53 e=17 -> n=3233, phi=3120, d=2753

import { sha256 } from "./sha256";

const SMALL_PRIMES = [
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n,
  53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n,
];

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

export function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

export function modInv(a: bigint, m: bigint): bigint {
  const [g, s] = egcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error(`${a} 在模 ${m} 下无乘法逆元`);
  return ((s % m) + m) % m;
}

export function egcdTrace(a: bigint, m: bigint): { steps: { q: bigint; r0: bigint; r1: bigint; s0: bigint; s1: bigint }[]; inv: bigint } {
  // 复刻 Python 的 (r0,s0)/(r1,s1) 迭代过程, 供课堂展示扩展欧几里得步骤
  let r0 = ((a % m) + m) % m;
  let r1 = m;
  let s0 = 1n;
  let s1 = 0n;
  const steps: { q: bigint; r0: bigint; r1: bigint; s0: bigint; s1: bigint }[] = [];
  while (r1) {
    const q = r0 / r1;
    steps.push({ q, r0, r1, s0, s1 });
    const nr0 = r1;
    const nr1 = r0 - q * r1;
    const ns0 = s1;
    const ns1 = s0 - q * s1;
    r0 = nr0;
    r1 = nr1;
    s0 = ns0;
    s1 = ns1;
  }
  if (r0 !== 1n) throw new Error(`${a} 在模 ${m} 下无乘法逆元`);
  return { steps, inv: ((s0 % m) + m) % m };
}

// ---- Miller-Rabin (确定性基: 用前几个素数做底, 对 < 3.3e24 严格; 课堂再加随机轮) ----
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

export function millerRabin(
  n: bigint,
  k = 20,
  trace?: string[],
): boolean {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let r = 0n;
  let d = n - 1n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1n;
  }
  for (let i = 0; i < k; i++) {
    const a = 2n + randBelow(n - 3n); // a ∈ [2, n-2]
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) {
      if (trace) trace.push(`轮 ${i + 1}: a=${a} 首步即通过 (x=${x})`);
      continue;
    }
    let composite = true;
    for (let j = 0n; j < r - 1n; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) {
      if (trace) trace.push(`轮 ${i + 1}: a=${a} 发现合数, 返回 False`);
      return false;
    }
    if (trace) trace.push(`轮 ${i + 1}: a=${a} 见证通过`);
  }
  return true;
}

export function genPrime(bits: number): bigint {
  if (bits < 8) throw new Error("素数比特长度至少 8");
  for (;;) {
    const candidate = randBelow(1n << BigInt(bits)) | (1n << BigInt(bits - 1)) | 1n;
    if (millerRabin(candidate)) return candidate;
  }
}

// ---- 密钥对 ----
export interface RSAKey {
  n: bigint;
  e: bigint;
  d: bigint;
  p: bigint;
  q: bigint;
  dp: bigint;
  dq: bigint;
  qinv: bigint;
}

export function keyFromPQ(p: bigint, q: bigint, e = 65537n): RSAKey {
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  if (gcd(e, phi) !== 1n) throw new Error(`e 与 φ(n) 不互素`);
  const d = modInv(e, phi);
  const dp = d % (p - 1n);
  const dq = d % (q - 1n);
  const qinv = modInv(q, p);
  return { n, e, d, p, q, dp, dq, qinv };
}

export function generateKey(bits = 256, e = 65537n): RSAKey {
  if (bits < 64) throw new Error("bits 太小");
  const half = Math.floor(bits / 2);
  for (;;) {
    const p = genPrime(half);
    const q = genPrime(bits - half);
    if (p === q) continue;
    try {
      return keyFromPQ(p, q, e);
    } catch {
      continue;
    }
  }
}

export function encrypt(m: bigint, n: bigint, e: bigint): bigint {
  if (!(m >= 0n && m < n)) {
    throw new Error(`明文 m 必须满足 0 ≤ m < n, 当前 m=${m}, n bits=${n.toString(2).length}`);
  }
  return modPow(m, e, n);
}

export function decrypt(c: bigint, n: bigint, d: bigint): bigint {
  return modPow(c, d, n);
}

export function decryptCRT(c: bigint, key: RSAKey): bigint {
  // m1 = c^dp mod p, m2 = c^dq mod q, h = qinv·(m1-m2) mod p, m = m2 + h·q
  const m1 = modPow(c, key.dp, key.p);
  const m2 = modPow(c, key.dq, key.q);
  const h = ((((key.qinv * (m1 - m2)) % key.p) + key.p) % key.p);
  return m2 + h * key.q;
}

// ---- 签名 (裸 RSA + SHA-256 截断) ----
export function hashToInt(message: string, n: bigint): bigint {
  const bytes = new TextEncoder().encode(message);
  const h = sha256(bytes);
  const maxBytes = Math.floor((n.toString(2).length - 1) / 8);
  const used = maxBytes < h.length ? h.slice(0, maxBytes) : h;
  let v = 0n;
  for (const b of used) v = (v << 8n) | BigInt(b);
  return v % n;
}

export function sign(message: string, key: RSAKey): bigint {
  return modPow(hashToInt(message, key.n), key.d, key.n);
}

export function verify(message: string, signature: bigint, n: bigint, e: bigint): boolean {
  return modPow(signature, e, n) === hashToInt(message, n);
}

// ---- 创新点: 低 e 立方根攻击 ----
export function integerCubeRoot(x: bigint): bigint {
  if (x < 0n) throw new Error("要求非负整数");
  if (x < 2n) return x;
  let r = 1n << BigInt(Math.floor((x.toString(2).length + 2) / 3));
  for (;;) {
    const nr = (2n * r + x / (r * r)) / 3n;
    if (nr >= r) return r;
    r = nr;
  }
}

export function lowExponentAttack(c: bigint, e = 3n): bigint {
  if (e !== 3n) throw new Error("此教学攻击仅演示 e=3 的情形");
  const m = integerCubeRoot(c);
  if (m * m * m !== c) {
    throw new Error("立方根不是整数, 说明 m^3 ≥ n, 该攻击不适用");
  }
  return m;
}
