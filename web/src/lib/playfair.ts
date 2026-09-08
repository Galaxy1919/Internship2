// Playfair Cipher (双字母组替代 / digraph substitution)
// 5x5 方阵, I/J 合并; 三种几何规则: 同行右移 / 同列下移 / 矩形换列
// 参考向量 (Wikipedia): key="playfair example", plain="Hide the gold in the tree stump"
//   -> cipher = BMODZBXDNABEKUDMUIXMMOUVIF

export const ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 25 个字母, 无 J
export const SIZE = 5;

export function normalizeKey(key: string): string {
  const seen = new Set<string>();
  let out = "";
  for (let ch of key.toUpperCase()) {
    if (!/[A-Z]/.test(ch)) continue;
    if (ch === "J") ch = "I";
    if (seen.has(ch)) continue;
    seen.add(ch);
    out += ch;
  }
  return out;
}

export function buildSquare(key = ""): string {
  const norm = normalizeKey(key);
  let letters = norm;
  for (const ch of ALPHABET) if (!norm.includes(ch)) letters += ch;
  if (letters.length !== 25) throw new Error(`方阵字母数异常: ${letters.length}(应为 25)`);
  return letters;
}

export function formatSquareRows(square: string): string[][] {
  const rows: string[][] = [];
  for (let r = 0; r < SIZE; r++) rows.push(square.slice(r * SIZE, (r + 1) * SIZE).split(""));
  return rows;
}

export function posOf(square: string, ch: string): [number, number] {
  const idx = square.indexOf(ch);
  if (idx < 0) throw new Error(`字母 ${ch} 不在方阵中`);
  return [Math.floor(idx / SIZE), idx % SIZE];
}

// 预处理: 去非字母 -> 大写 -> J->I; 相邻相同字母间插 X; 末尾单字母补 X
export function preparePlaintext(text: string): string {
  let s = "";
  for (let ch of text.toUpperCase()) {
    if (!/[A-Z]/.test(ch)) continue;
    s += ch === "J" ? "I" : ch;
  }
  let out = "";
  let i = 0;
  while (i < s.length) {
    const a = s[i];
    const b = i + 1 < s.length ? s[i + 1] : "X";
    if (a === b) {
      out += a + "X";
      i += 1;
    } else {
      out += a + b;
      i += 2;
    }
  }
  return out;
}

export function digraphsOf(prepared: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < prepared.length; i += 2) out.push(prepared.slice(i, i + 2));
  return out;
}

export function encryptPair(square: string, a: string, b: string): string {
  const [ra, ca] = posOf(square, a);
  const [rb, cb] = posOf(square, b);
  if (ra === rb) return square[ra * SIZE + ((ca + 1) % SIZE)] + square[rb * SIZE + ((cb + 1) % SIZE)];
  if (ca === cb) return square[((ra + 1) % SIZE) * SIZE + ca] + square[((rb + 1) % SIZE) * SIZE + cb];
  return square[ra * SIZE + cb] + square[rb * SIZE + ca];
}

export function decryptPair(square: string, a: string, b: string): string {
  const [ra, ca] = posOf(square, a);
  const [rb, cb] = posOf(square, b);
  if (ra === rb) return square[ra * SIZE + ((ca - 1 + SIZE) % SIZE)] + square[rb * SIZE + ((cb - 1 + SIZE) % SIZE)];
  if (ca === cb) return square[((ra - 1 + SIZE) % SIZE) * SIZE + ca] + square[((rb - 1 + SIZE) % SIZE) * SIZE + cb];
  return square[ra * SIZE + cb] + square[rb * SIZE + ca];
}

export function encrypt(plain: string, key = ""): string {
  const square = buildSquare(key);
  const prepared = preparePlaintext(plain);
  let out = "";
  for (const d of digraphsOf(prepared)) out += encryptPair(square, d[0], d[1]);
  return out;
}

export function decrypt(cipher: string, key = ""): string {
  const square = buildSquare(key);
  const c = cipher.toUpperCase().replace(/[^A-Z]/g, "");
  if (c.length % 2 !== 0) throw new Error("密文字母个数不是偶数, 无法按双字母组切分");
  let out = "";
  for (let i = 0; i < c.length; i += 2) out += decryptPair(square, c[i], c[i + 1]);
  return out;
}

export type TraceStep = {
  pair: string;
  rule: "同行→右移" | "同列→下移" | "矩形→换列";
  aPos: [number, number]; // 1-based
  bPos: [number, number];
  out: string;
};

export function trace(plain: string, key = ""): {
  square: string;
  prepared: string;
  ciphertext: string;
  steps: TraceStep[];
} {
  const square = buildSquare(key);
  const prepared = preparePlaintext(plain);
  const steps: TraceStep[] = [];
  for (const d of digraphsOf(prepared)) {
    const a = d[0];
    const b = d[1];
    const [ra0, ca0] = posOf(square, a);
    const [rb0, cb0] = posOf(square, b);
    let rule: TraceStep["rule"];
    if (ra0 === rb0) rule = "同行→右移";
    else if (ca0 === cb0) rule = "同列→下移";
    else rule = "矩形→换列";
    const out = encryptPair(square, a, b);
    steps.push({
      pair: d,
      rule,
      aPos: [ra0 + 1, ca0 + 1],
      bPos: [rb0 + 1, cb0 + 1],
      out,
    });
  }
  return { square, prepared, ciphertext: encrypt(plain, key), steps };
}
