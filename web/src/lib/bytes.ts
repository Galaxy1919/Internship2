// 通用字节工具:UTF-8 编解码、hex 编解码、位差异统计
export const encoder = new TextEncoder();
export const decoder = new TextDecoder("utf-8", { fatal: false });

export const strToBytes = (s: string): Uint8Array => encoder.encode(s);
export const bytesToStr = (b: Uint8Array): string => decoder.decode(b);

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(h: string): Uint8Array {
  const clean = h.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex 长度必须为偶数");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error(`非法 hex 字符于位置 ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

// 数一下两段等长字节之间不同的比特数
export function bitDiff(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  let d = 0;
  for (let i = 0; i < n; i++) {
    let x = a[i] ^ b[i];
    while (x) {
      d += x & 1;
      x >>>= 1;
    }
  }
  return d;
}

export const bitRatio = (a: Uint8Array, b: Uint8Array): number =>
  bitDiff(a, b) / (Math.min(a.length, b.length) * 8 || 1);
