// ECC 椭圆曲线教学实现 (BigInt)
// 对齐 Python publicKey/ECC/main.py:
//   - 短 Weierstrass 曲线 y^2 = x^3 + a·x + b (mod p), 无穷远点用 null
//   - toy 曲线 p=17 a=2 b=2 G=(5,1) n=19 (2G=(6,3), 19G=O 手算向量)
//   - secp256k1 真实参数 (2G 已知向量)
//   - double-and-add 可审计轨迹
//   - ECDH + 公钥合法性检查 (防小子群/无效曲线攻击入门)

export interface Curve {
  name: string;
  p: bigint;
  a: bigint;
  b: bigint;
  Gx: bigint;
  Gy: bigint;
  n: bigint; // 基点 G 的阶
}

export type Point = { x: bigint; y: bigint } | null;

export function G(C: Curve): Point {
  return { x: C.Gx, y: C.Gy };
}

// ---- 曲线参数 ----
export const TOY: Curve = {
  name: "toy-p17",
  p: 17n,
  a: 2n,
  b: 2n,
  Gx: 5n,
  Gy: 1n,
  n: 19n,
};

export const SECP256K1: Curve = {
  name: "secp256k1",
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
};

// secp256k1 2G 公开已知向量
export const SECP256K1_2G = {
  x: 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n,
  y: 0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52an,
};

// ---- 有限域 ----
export function modInv(x: bigint, p: bigint): bigint {
  if (x % p === 0n) throw new Error("0 在有限域里没有乘法逆元");
  // 扩展欧几里得
  let [r0, r1, s0, s1] = [((x % p) + p) % p, p, 1n, 0n];
  while (r1) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error(`${x} 无模逆`);
  return ((s0 % p) + p) % p;
}

export function isOnCurve(P: Point, C: Curve): boolean {
  if (!P) return true;
  const { x, y } = P;
  return (((y * y - (x * x * x + C.a * x + C.b)) % C.p) + C.p) % C.p === 0n;
}

export function pointNeg(P: Point, C: Curve): Point {
  if (!P) return null;
  return { x: P.x, y: ((C.p - P.y) % C.p + C.p) % C.p };
}

export function pointAdd(P: Point, Q: Point, C: Curve): Point {
  if (!P) return Q;
  if (!Q) return P;
  const { x: x1, y: y1 } = P;
  const { x: x2, y: y2 } = Q;

  // P = -Q -> 无穷远
  if (x1 === x2 && (((y1 + y2) % C.p) + C.p) % C.p === 0n) return null;

  let lam: bigint;
  if (P.x === Q.x && P.y === Q.y) {
    lam = (((3n * x1 * x1 + C.a) % C.p) * modInv((2n * y1) % C.p, C.p)) % C.p;
  } else {
    lam = ((((y2 - y1) % C.p) + C.p) % C.p * modInv((((x2 - x1) % C.p) + C.p) % C.p, C.p)) % C.p;
  }
  const x3 = (((lam * lam - x1 - x2) % C.p) + C.p) % C.p;
  const y3 = (((lam * (x1 - x3) - y1) % C.p) + C.p) % C.p;
  return { x: x3, y: y3 };
}

export type ScalarStep = { op: "add" | "double"; bit: number; pt: Point };

export function scalarMul(k: bigint, P: Point, C: Curve, trace?: ScalarStep[]): Point {
  if (k === 0n || !P) return null;
  if (k < 0n) return scalarMul(-k, pointNeg(P, C), C, trace);

  let result: Point = null;
  let addend: Point = P;
  let bitIndex = 0;
  let kk = k;
  while (kk > 0n) {
    if (kk & 1n) {
      result = pointAdd(result, addend, C);
      if (trace) trace.push({ op: "add", bit: bitIndex, pt: result });
    }
    addend = pointAdd(addend, addend, C);
    if (trace && (kk >> 1n) > 0n) trace.push({ op: "double", bit: bitIndex, pt: addend });
    kk >>= 1n;
    bitIndex += 1;
  }
  return result;
}

// ---- 密钥对 / ECDH ----
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

export function randomScalar(max: bigint): bigint {
  return 1n + randBelow(max - 1n);
}

export function generateKeypair(C: Curve, d?: bigint): { d: bigint; pub: Point } {
  const priv = d !== undefined ? d : randomScalar(C.n);
  return { d: priv, pub: scalarMul(priv, G(C), C) };
}

export function publicKeyIsValid(pub: Point, C: Curve): boolean {
  if (!pub) return false;
  const { x, y } = pub;
  if (!(x >= 0n && x < C.p && y >= 0n && y < C.p)) return false;
  if (!isOnCurve(pub, C)) return false;
  return scalarMul(C.n, pub, C) === null; // 子群成员测试
}

export function ecdh(myPriv: bigint, peerPub: Point, C: Curve): Point {
  if (!publicKeyIsValid(peerPub, C)) {
    throw new Error("对端公钥不合法(曲线外、无穷远或不在正确子群)");
  }
  return scalarMul(myPriv, peerPub, C);
}

export function pointToStr(P: Point, short = false): string {
  if (!P) return "O (无穷远)";
  const fmt = (v: bigint) => {
    if (!short) return v.toString(); // toy 曲线直接十进制, 便于手算核对
    const s = v.toString(16);
    return s.length > 16 ? s.slice(0, 8) + "…" + s.slice(-4) : s;
  };
  return `(${fmt(P.x)}, ${fmt(P.y)})`;
}
