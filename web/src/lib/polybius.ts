// Polybius Square (Multiliteral, 5x5) - 单表替换的多字符版
// I/J 合并为 I, 支持带关键字的方阵

const ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 无 J
const SIZE = 5;

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
  if (letters.length !== 25) throw new Error("方阵字母数应为 25");
  return letters;
}

export function buildTables(square: string): {
  encode: Record<string, string>;
  decode: Record<string, string>;
} {
  const encode: Record<string, string> = {};
  const decode: Record<string, string> = {};
  for (let idx = 0; idx < square.length; idx++) {
    const row = Math.floor(idx / SIZE) + 1;
    const col = (idx % SIZE) + 1;
    const code = `${row}${col}`;
    encode[square[idx]] = code;
    decode[code] = square[idx];
  }
  return { encode, decode };
}

export function polybiusEncrypt(plain: string, key = "", sep = " "): string {
  const { encode } = buildTables(buildSquare(key));
  const parts: string[] = [];
  for (let ch of plain.toUpperCase()) {
    if (ch === "J") ch = "I";
    const c = encode[ch];
    if (c) parts.push(c);
  }
  return parts.join(sep);
}

export function polybiusDecrypt(cipher: string, key = ""): string {
  const { decode } = buildTables(buildSquare(key));
  const digits = cipher.replace(/\D+/g, "");
  if (digits.length % 2 !== 0) throw new Error("密文数字个数不是偶数,无法按 2 位一组切分");
  let out = "";
  for (let i = 0; i < digits.length; i += 2) {
    const pair = digits.substr(i, 2);
    const letter = decode[pair];
    if (!letter) throw new Error(`非法坐标 ${pair} (每一位应在 1-5)`);
    out += letter;
  }
  return out;
}

export function formatSquareRows(square: string): string[][] {
  const rows: string[][] = [];
  for (let r = 0; r < SIZE; r++) {
    rows.push(square.slice(r * SIZE, (r + 1) * SIZE).split(""));
  }
  return rows;
}
