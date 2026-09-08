// SM2 国密椭圆曲线密码 (BigInt + 手写 SM3)
// 对齐 Python publicKey/SM2/main.py:
//   - SM3 摘要 (GM/T 0004-2012, 官方向量 "abc"=66c7f0f462eeedd9d1f2d46bdc10e4e2...)
//   - SM2 固定 256-bit 曲线参数 (GM/T 0003.5)
//   - SM2-DSA 签名/验证 (ZA 身份预处理, 默认 ID "1234567812345678")
//   - SM2-PKE 加密/解密 (C1||C3||C2, KDF 用 SM3, C3 完整性校验)

// ---------------------------------------------------------------------------
// SM3 (32-bit words, 无符号)
// ---------------------------------------------------------------------------

const SM3_IV = new Uint32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
]);

function rotl32(x: number, n: number): number {
  n &= 31;
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function p0(x: number): number {
  return (x ^ rotl32(x, 9) ^ rotl32(x, 17)) >>> 0;
}

function p1(x: number): number {
  return (x ^ rotl32(x, 15) ^ rotl32(x, 23)) >>> 0;
}

function ff(j: number, x: number, y: number, z: number): number {
  if (j < 16) return (x ^ y ^ z) >>> 0;
  return ((x & y) | (x & z) | (y & z)) >>> 0;
}

function gg(j: number, x: number, y: number, z: number): number {
  if (j < 16) return (x ^ y ^ z) >>> 0;
  return ((x & y) | (~x & z)) >>> 0;
}

export function sm3(data: Uint8Array): Uint8Array {
  const bitLen = data.length * 8;
  const rem = data.length % 64;
  const padLen = rem < 56 ? 56 - rem : 120 - rem;
  const buf = new Uint8Array(data.length + padLen + 8);
  buf.set(data);
  buf[data.length] = 0x80;
  const dv = new DataView(buf.buffer);
  // 末尾 8 字节大端位长度 (JS number 安全上限内: 数据长度必须 < 2^29 字节)
  dv.setUint32(buf.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(buf.length - 4, bitLen >>> 0);

  const V = SM3_IV.slice();
  const W = new Uint32Array(68);
  const Wp = new Uint32Array(64);

  for (let off = 0; off < buf.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 68; i++) {
      W[i] = (p1(W[i - 16] ^ W[i - 9] ^ rotl32(W[i - 3], 15)) ^ rotl32(W[i - 13], 7) ^ W[i - 6]) >>> 0;
    }
    for (let i = 0; i < 64; i++) Wp[i] = (W[i] ^ W[i + 4]) >>> 0;

    let [A, B, C, D, E, F, G, H] = V;
    for (let j = 0; j < 64; j++) {
      const T = j < 16 ? 0x79cc4519 : 0x7a879d8a;
      const SS1 = rotl32((rotl32(A, 12) + E + rotl32(T, j)) >>> 0, 7);
      const SS2 = (SS1 ^ rotl32(A, 12)) >>> 0;
      const TT1 = (ff(j, A, B, C) + D + SS2 + Wp[j]) >>> 0;
      const TT2 = (gg(j, E, F, G) + H + SS1 + W[j]) >>> 0;
      D = C;
      C = rotl32(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = rotl32(F, 19);
      F = E;
      E = p0(TT2);
    }
    const nv = [A, B, C, D, E, F, G, H];
    for (let i = 0; i < 8; i++) V[i] = (V[i] ^ nv[i]) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, V[i]);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

// ---------------------------------------------------------------------------
// SM2 曲线 (GM/T 0003.5-2012)
// ---------------------------------------------------------------------------

export const SM2_CURVE = {
  p: 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn,
  a: 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn,
  b: 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n,
  Gx: 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n,
  Gy: 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n,
  n: 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n,
};

export type Sm2Point = { x: bigint; y: bigint } | null;

function modInvFp(x: bigint, p: bigint): bigint {
  let [r0, r1, s0, s1] = [((x % p) + p) % p, p, 1n, 0n];
  while (r1) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("模逆不存在");
  return ((s0 % p) + p) % p;
}

function isOnCurve(P: Sm2Point): boolean {
  if (!P) return true;
  const C = SM2_CURVE;
  return (((P.y * P.y - (P.x * P.x * P.x + C.a * P.x + C.b)) % C.p) + C.p) % C.p === 0n;
}

function pointAdd(P: Sm2Point, Q: Sm2Point): Sm2Point {
  const C = SM2_CURVE;
  if (!P) return Q;
  if (!Q) return P;
  if (P.x === Q.x && (((P.y + Q.y) % C.p) + C.p) % C.p === 0n) return null;
  let lam: bigint;
  if (P.x === Q.x && P.y === Q.y) {
    lam = (((3n * P.x * P.x + C.a) % C.p) * modInvFp((2n * P.y) % C.p, C.p)) % C.p;
  } else {
    lam = ((((Q.y - P.y) % C.p) + C.p) % C.p * modInvFp((((Q.x - P.x) % C.p) + C.p) % C.p, C.p)) % C.p;
  }
  const x3 = (((lam * lam - P.x - Q.x) % C.p) + C.p) % C.p;
  const y3 = (((lam * (P.x - x3) - P.y) % C.p) + C.p) % C.p;
  return { x: x3, y: y3 };
}

function scalarMul(k: bigint, P: Sm2Point): Sm2Point {
  const C = SM2_CURVE;
  if (k === 0n || !P) return null;
  if (k < 0n) {
    const neg = { x: P.x, y: ((C.p - P.y) % C.p + C.p) % C.p };
    return scalarMul(-k, neg);
  }
  let result: Sm2Point = null;
  let addend: Sm2Point = P;
  let kk = k;
  while (kk > 0n) {
    if (kk & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    kk >>= 1n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// 密钥对 / ZA 预处理
// ---------------------------------------------------------------------------

const DEFAULT_ID = new TextEncoder().encode("1234567812345678");

function intToBytes32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  const dv = new DataView(out.buffer);
  let hex = x.toString(16).padStart(64, "0");
  for (let i = 0; i < 32; i++) dv.setUint8(i, parseInt(hex.slice(i * 2, i * 2 + 2), 16));
  return out;
}

export function computeZA(userId: Uint8Array, pub: Sm2Point): Uint8Array {
  if (!pub) throw new Error("公钥不能是无穷远");
  const C = SM2_CURVE;
  // ENTL || ID || a || b || xG || yG || xA || yA
  const entl = new Uint8Array(2);
  new DataView(entl.buffer).setUint16(0, userId.length * 8);
  const parts = [
    entl,
    userId,
    intToBytes32(C.a),
    intToBytes32(C.b),
    intToBytes32(C.Gx),
    intToBytes32(C.Gy),
    intToBytes32(pub.x),
    intToBytes32(pub.y),
  ];
  let total = 0;
  for (const p of parts) total += p.length;
  const body = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    body.set(p, off);
    off += p.length;
  }
  return sm3(body);
}

function randBelow(n: bigint): bigint {
  const bytes = Math.ceil(n.toString(2).length / 8) + 1;
  const buf = new Uint8Array(bytes);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) crypto.getRandomValues(buf);
  else for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  let v = 0n;
  for (let i = 0; i < bytes; i++) v = (v << 8n) | BigInt(buf[i]);
  return v % n;
}

export function generateKeypair(): { d: bigint; pub: Sm2Point } {
  const d = 1n + randBelow(SM2_CURVE.n - 1n);
  return { d, pub: scalarMul(d, { x: SM2_CURVE.Gx, y: SM2_CURVE.Gy }) };
}

// ---------------------------------------------------------------------------
// SM2-DSA 签名 / 验证
// ---------------------------------------------------------------------------

export function sm2Sign(
  msg: Uint8Array,
  d: bigint,
  pub: Sm2Point,
  userId: Uint8Array = DEFAULT_ID,
  k?: bigint,
): { r: bigint; s: bigint; e: bigint; za: Uint8Array } {
  const C = SM2_CURVE;
  const za = computeZA(userId, pub);
  const zaMsg = new Uint8Array(za.length + msg.length);
  zaMsg.set(za, 0);
  zaMsg.set(msg, za.length);
  const e = bigintFromBytes(sm3(zaMsg));

  for (;;) {
    let kk = k;
    if (kk === undefined) kk = 1n + randBelow(C.n - 1n);
    const P1 = scalarMul(kk, { x: C.Gx, y: C.Gy });
    if (!P1) {
      if (k !== undefined) throw new Error("指定的 k 生成无穷远点");
      continue;
    }
    const r = (e + P1.x) % C.n;
    if (r === 0n || (r + kk) % C.n === 0n) {
      if (k !== undefined) throw new Error("指定的 k 无效(r=0 或 r+k=n)");
      continue;
    }
    // s = (1+d)^-1 · (k - r·d) mod n
    const s = (modInvFp(1n + d, C.n) * (((kk - r * d) % C.n) + C.n) % C.n) % C.n;
    if (s === 0n) {
      if (k !== undefined) throw new Error("指定的 k 导致 s=0");
      continue;
    }
    return { r, s, e, za };
  }
}

export function sm2Verify(
  msg: Uint8Array,
  r: bigint,
  s: bigint,
  pub: Sm2Point,
  userId: Uint8Array = DEFAULT_ID,
): boolean {
  const C = SM2_CURVE;
  if (!(r >= 1n && r < C.n && s >= 1n && s < C.n)) return false;
  const za = computeZA(userId, pub);
  const zaMsg = new Uint8Array(za.length + msg.length);
  zaMsg.set(za, 0);
  zaMsg.set(msg, za.length);
  const e = bigintFromBytes(sm3(zaMsg));
  const t = (r + s) % C.n;
  if (t === 0n) return false;
  const P = pointAdd(scalarMul(s, { x: C.Gx, y: C.Gy }), scalarMul(t, pub));
  if (!P) return false;
  return (e + P.x) % C.n === r;
}

// ---------------------------------------------------------------------------
// SM2-PKE (C1||C3||C2)
// ---------------------------------------------------------------------------

function kdfSm3(z: Uint8Array, klen: number): Uint8Array {
  const out: number[] = [];
  let ct = 1;
  while (out.length < klen) {
    const ctb = new Uint8Array(4);
    new DataView(ctb.buffer).setUint32(0, ct);
    const joined = new Uint8Array(z.length + 4);
    joined.set(z, 0);
    joined.set(ctb, z.length);
    const h = sm3(joined);
    for (const b of h) out.push(b);
    ct += 1;
  }
  return new Uint8Array(out.slice(0, klen));
}

export function sm2Encrypt(msg: Uint8Array, pub: Sm2Point, k?: bigint): { ct: Uint8Array; kUsed: bigint } {
  const C = SM2_CURVE;
  for (;;) {
    let kk = k;
    if (kk === undefined) kk = 1n + randBelow(C.n - 1n);
    const C1 = scalarMul(kk, { x: C.Gx, y: C.Gy });
    const S = scalarMul(kk, pub);
    if (!C1 || !S) {
      if (k !== undefined) throw new Error("指定的 k 得到无穷远点");
      continue;
    }
    const x2 = intToBytes32(S.x);
    const y2 = intToBytes32(S.y);
    const xy = new Uint8Array(64);
    xy.set(x2, 0);
    xy.set(y2, 32);
    const t = kdfSm3(xy, msg.length);
    let allZero = true;
    for (const b of t) if (b !== 0) { allZero = false; break; }
    if (allZero) {
      if (k !== undefined) throw new Error("指定的 k 使 KDF 全 0");
      continue;
    }
    const c2 = new Uint8Array(msg.length);
    for (let i = 0; i < msg.length; i++) c2[i] = msg[i] ^ t[i];
    // C3 = SM3(x2 || M || y2)
    const c3body = new Uint8Array(64 + msg.length);
    c3body.set(x2, 0);
    c3body.set(msg, 32);
    c3body.set(y2, 32 + msg.length);
    const c3 = sm3(c3body);
    // 04 || x1 || y1 || C3 || C2
    const ct = new Uint8Array(1 + 64 + 32 + msg.length);
    ct[0] = 0x04;
    ct.set(intToBytes32(C1.x), 1);
    ct.set(intToBytes32(C1.y), 33);
    ct.set(c3, 65);
    ct.set(c2, 97);
    return { ct, kUsed: kk };
  }
}

export function sm2Decrypt(ct: Uint8Array, d: bigint): Uint8Array {
  if (ct.length < 1 + 64 + 32) throw new Error("密文过短");
  if (ct[0] !== 0x04) throw new Error("仅支持未压缩点格式 (04 前缀)");
  const C = SM2_CURVE;
  const x1 = bigintFromBytes(ct.slice(1, 33));
  const y1 = bigintFromBytes(ct.slice(33, 65));
  const C1 = { x: x1, y: y1 };
  if (!isOnCurve(C1)) throw new Error("C1 不在曲线上");
  const c3 = ct.slice(65, 97);
  const c2 = ct.slice(97);
  const S = scalarMul(d, C1);
  if (!S) throw new Error("解密失败: d·C1 = O");
  const x2 = intToBytes32(S.x);
  const y2 = intToBytes32(S.y);
  const xy = new Uint8Array(64);
  xy.set(x2, 0);
  xy.set(y2, 32);
  const t = kdfSm3(xy, c2.length);
  const m = new Uint8Array(c2.length);
  for (let i = 0; i < c2.length; i++) m[i] = c2[i] ^ t[i];
  const c3body = new Uint8Array(64 + m.length);
  c3body.set(x2, 0);
  c3body.set(m, 32);
  c3body.set(y2, 32 + m.length);
  const c3Check = sm3(c3body);
  if (bytesToHex(c3Check) !== bytesToHex(c3)) throw new Error("完整性校验失败 (C3 不匹配)");
  return m;
}

export function bigintFromBytes(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}
