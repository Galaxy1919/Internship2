// MD5 from scratch, 与 RFC 1321 一致
// 用 Uint32Array + 二进制位操作,浏览器里跑得动

const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const T: number[] = (() => {
  const arr: number[] = [];
  for (let i = 0; i < 64; i++) arr.push(Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
  return arr;
})();

const A0 = 0x67452301;
const B0 = 0xefcdab89;
const C0 = 0x98badcfe;
const D0 = 0x10325476;

const rotl = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0;

function padMessage(msg: Uint8Array): Uint8Array {
  const origLenBits = BigInt(msg.length) * 8n;
  let padLen = 56 - ((msg.length + 1) % 64);
  if (padLen < 0) padLen += 64;
  const out = new Uint8Array(msg.length + 1 + padLen + 8);
  out.set(msg, 0);
  out[msg.length] = 0x80;
  // 小端 64 位长度
  const lenBytes = new DataView(out.buffer, out.byteOffset + msg.length + 1 + padLen, 8);
  lenBytes.setBigUint64(0, origLenBits & 0xffffffffffffffffn, true);
  return out;
}

export function md5(msg: Uint8Array): Uint8Array {
  const padded = padMessage(msg);
  let a = A0, b = B0, c = C0, d = D0;
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const M = new Uint32Array(16);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(off + i * 4, true);
    let A = a, B = b, C = c, D = d;

    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) {
        f = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        f = (B & D) | (C & ~D);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        f = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      f = f >>> 0;
      const temp = (A + f + T[i] + M[g]) >>> 0;
      const nb = (B + rotl(temp, S[i])) >>> 0;
      A = D;
      D = C;
      C = B;
      B = nb;
    }
    a = (a + A) >>> 0;
    b = (b + B) >>> 0;
    c = (c + C) >>> 0;
    d = (d + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, a, true);
  dv.setUint32(4, b, true);
  dv.setUint32(8, c, true);
  dv.setUint32(12, d, true);
  return out;
}

export function md5Hex(msg: Uint8Array): string {
  const digest = md5(msg);
  let s = "";
  for (const x of digest) s += x.toString(16).padStart(2, "0");
  return s;
}
