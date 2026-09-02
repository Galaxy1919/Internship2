// 小规模 Diffie-Hellman 密钥交换 + 可审计交换记录 + 篡改演示
// BigInt 实现,避免 pow 溢出

export function fastPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 1n || exponent < 0n) throw new Error("模数必须大于1,指数不能为负数");
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

export function fastPowTrace(
  base: bigint,
  exponent: bigint,
  modulus: bigint,
): { result: bigint; steps: { exponent: bigint; base: bigint; result: bigint }[] } {
  const steps: { exponent: bigint; base: bigint; result: bigint }[] = [];
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    steps.push({ exponent: e, base: b, result });
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return { result, steps };
}

export function publicValue(privateKey: bigint, prime: bigint, generator: bigint): bigint {
  if (privateKey <= 1n || privateKey >= prime - 1n) {
    throw new Error("私有值应位于 2 到 p-2 之间");
  }
  return fastPow(generator, privateKey, prime);
}

export function sharedSecret(peerPublic: bigint, privateKey: bigint, prime: bigint): bigint {
  if (!(peerPublic > 1n && peerPublic < prime)) {
    throw new Error("收到的公开值不在合法范围内");
  }
  return fastPow(peerPublic, privateKey, prime);
}

// 派生密钥:直接把共享秘密的 SHA-256 hex 前缀截断 (使用 WebCrypto)
export async function deriveKeyHex(
  secret: bigint,
  label: string,
  bytes: number,
): Promise<string> {
  const secretBytes = bigIntToBytes(secret);
  const labeled = new Uint8Array(secretBytes.length + label.length);
  labeled.set(secretBytes, 0);
  for (let i = 0; i < label.length; i++) labeled[secretBytes.length + i] = label.charCodeAt(i);
  const hashBuf = await crypto.subtle.digest("SHA-256", labeled);
  const view = new Uint8Array(hashBuf);
  let hex = "";
  for (let i = 0; i < bytes; i++) hex += view[i % view.length].toString(16).padStart(2, "0");
  return hex;
}

export function bigIntToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0]);
  const chunks: number[] = [];
  let x = n;
  while (x > 0n) {
    chunks.unshift(Number(x & 0xffn));
    x >>= 8n;
  }
  return new Uint8Array(chunks);
}

export interface ExchangeRecord {
  p: bigint;
  g: bigint;
  alicePriv: bigint;
  bobPriv: bigint;
  alicePub: bigint;
  bobPub: bigint;
  aliceSecret: bigint;
  bobSecret: bigint;
  sameSecret: boolean;
}

export function exchange(p: bigint, g: bigint, aPriv: bigint, bPriv: bigint): ExchangeRecord {
  if (p <= 3n) throw new Error("素数参数过小");
  if (!(g > 1n && g < p)) throw new Error("生成元必须满足 1 < g < p");
  const alicePub = publicValue(aPriv, p, g);
  const bobPub = publicValue(bPriv, p, g);
  const aliceSecret = sharedSecret(bobPub, aPriv, p);
  const bobSecret = sharedSecret(alicePub, bPriv, p);
  return {
    p, g,
    alicePriv: aPriv, bobPriv: bPriv,
    alicePub, bobPub,
    aliceSecret, bobSecret,
    sameSecret: aliceSecret === bobSecret,
  };
}

export function tamperDemo(rec: ExchangeRecord): { fakePub: bigint; fakeSecret: bigint; same: boolean } {
  // XOR 一位翻转
  const fakePub = rec.alicePub ^ 1n;
  const fakeSecret = sharedSecret(fakePub > 1n && fakePub < rec.p ? fakePub : rec.alicePub + 2n, rec.bobPriv, rec.p);
  return { fakePub, fakeSecret, same: fakeSecret === rec.aliceSecret };
}
