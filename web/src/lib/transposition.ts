// 列置换密码 (Columnar Transposition), 变长列布局:不补齐伪字符

import { strToBytes, bytesToStr } from "./bytes";

export function columnOrder(key: string): number[] {
  if (!key) throw new Error("密钥不能为空");
  const chars = [...key];
  if (new Set(chars).size !== chars.length) {
    throw new Error("为避免列编号歧义,密钥不能包含重复字符");
  }
  return chars
    .map((ch, i) => ({ ch, i }))
    .sort((a, b) => (a.ch === b.ch ? a.i - b.i : a.ch < b.ch ? -1 : 1))
    .map((x) => x.i);
}

export function columnLengths(dataLen: number, width: number): number[] {
  if (width <= 0) throw new Error("列数必须为正数");
  const full = Math.floor(dataLen / width);
  const rem = dataLen % width;
  const arr: number[] = [];
  for (let c = 0; c < width; c++) arr.push(full + (c < rem ? 1 : 0));
  return arr;
}

export function transEncryptBytes(raw: Uint8Array, key: string): Uint8Array {
  const order = columnOrder(key);
  const width = key.length;
  const lengths = columnLengths(raw.length, width);
  const chunks: Uint8Array[] = [];
  for (const col of order) {
    const arr = new Uint8Array(lengths[col]);
    let idx = 0;
    for (let i = col; i < raw.length; i += width) {
      if (idx < lengths[col]) arr[idx++] = raw[i];
    }
    chunks.push(arr);
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function transDecryptBytes(cipher: Uint8Array, key: string): Uint8Array {
  const width = key.length;
  const order = columnOrder(key);
  const lengths = columnLengths(cipher.length, width);
  const columns: Uint8Array[] = new Array(width);
  let cursor = 0;
  for (const col of order) {
    columns[col] = cipher.slice(cursor, cursor + lengths[col]);
    cursor += lengths[col];
  }
  const maxLen = Math.max(0, ...lengths);
  const out = new Uint8Array(cipher.length);
  let idx = 0;
  for (let row = 0; row < maxLen; row++) {
    for (let col = 0; col < width; col++) {
      if (row < columns[col].length) out[idx++] = columns[col][row];
    }
  }
  return out.slice(0, idx);
}

export function transEncrypt(plain: string, key: string): Uint8Array {
  return transEncryptBytes(strToBytes(plain), key);
}
export function transDecrypt(cipher: Uint8Array, key: string): string {
  return bytesToStr(transDecryptBytes(cipher, key));
}

export function traceMatrix(plain: string, key: string): {
  key: string;
  columnNumbers: number[];
  readOrder: number[];
  matrixRows: string[][];
} {
  const raw = strToBytes(plain);
  const width = key.length;
  const order = columnOrder(key);
  const rows: string[][] = [];
  for (let i = 0; i < raw.length; i += width) {
    const row: string[] = [];
    for (let j = 0; j < width && i + j < raw.length; j++) {
      row.push(String.fromCharCode(raw[i + j]));
    }
    rows.push(row);
  }
  return {
    key,
    columnNumbers: Array.from({ length: width }, (_, i) => i + 1),
    readOrder: order.map((i) => i + 1),
    matrixRows: rows,
  };
}
