// 多表替代密码: Vigenere / Autokey-明文 / Autokey-密文
// 对齐 Python ClassicalCiphers/PolyalphabeticSubstitution/main.py
// 已知向量:
//   Vigenere        LEMON/ATTACKATDAWN -> LXFOPVEFRNHR
//   Autokey-明文     QUEENLY/ATTACKATDAWN -> QNXEPVYTWTWP
//   Autokey-密文     KEY/ATTACK -> KXRKZB

export type Variant = "vigenere" | "autokey-plaintext" | "autokey-ciphertext";
export const VARIANTS: Variant[] = ["vigenere", "autokey-plaintext", "autokey-ciphertext"];

export function lettersOnly(text: string): string {
  let out = "";
  for (const ch of text.toUpperCase()) {
    if (ch >= "A" && ch <= "Z") out += ch;
  }
  return out;
}

function shift(c: string, k: string, decrypt = false): string {
  const sign = decrypt ? -1 : 1;
  return String.fromCharCode(
    ((c.charCodeAt(0) - 65 + sign * (k.charCodeAt(0) - 65) + 26) % 26) + 65,
  );
}

// ---- Vigenere: 密钥周期重复 ----
export function vigenereEncrypt(plain: string, key: string): string {
  const p = lettersOnly(plain);
  const k = lettersOnly(key);
  if (!k) throw new Error("密钥不能为空");
  let out = "";
  for (let i = 0; i < p.length; i++) out += shift(p[i], k[i % k.length]);
  return out;
}

export function vigenereDecrypt(cipher: string, key: string): string {
  const c = lettersOnly(cipher);
  const k = lettersOnly(key);
  if (!k) throw new Error("密钥不能为空");
  let out = "";
  for (let i = 0; i < c.length; i++) out += shift(c[i], k[i % k.length], true);
  return out;
}

// ---- Autokey-明文: 密钥 + 明文 ----
export function autokeyPlaintextEncrypt(plain: string, key: string): string {
  const p = lettersOnly(plain);
  const k = lettersOnly(key);
  if (!k) throw new Error("密钥不能为空");
  let out = "";
  for (let i = 0; i < p.length; i++) {
    const ks = i < k.length ? k[i] : p[i - k.length];
    out += shift(p[i], ks);
  }
  return out;
}

export function autokeyPlaintextDecrypt(cipher: string, key: string): string {
  const c = lettersOnly(cipher);
  const k = lettersOnly(key);
  if (!k) throw new Error("密钥不能为空");
  const out: string[] = [];
  for (let i = 0; i < c.length; i++) {
    const ks = i < k.length ? k[i] : out[i - k.length];
    out.push(shift(c[i], ks, true));
  }
  return out.join("");
}

// ---- Autokey-密文: 密钥 + 已生成密文 ----
export function autokeyCiphertextEncrypt(plain: string, key: string): string {
  const p = lettersOnly(plain);
  const k = lettersOnly(key);
  if (!k) throw new Error("密钥不能为空");
  const out: string[] = [];
  for (let i = 0; i < p.length; i++) {
    const ks = i < k.length ? k[i] : out[i - k.length];
    out.push(shift(p[i], ks));
  }
  return out.join("");
}

export function autokeyCiphertextDecrypt(cipher: string, key: string): string {
  const c = lettersOnly(cipher);
  const k = lettersOnly(key);
  if (!k) throw new Error("密钥不能为空");
  const out: string[] = [];
  for (let i = 0; i < c.length; i++) {
    const ks = i < k.length ? k[i] : c[i - k.length];
    out.push(shift(c[i], ks, true));
  }
  return out.join("");
}

export function encrypt(plain: string, key: string, variant: Variant): string {
  switch (variant) {
    case "vigenere": return vigenereEncrypt(plain, key);
    case "autokey-plaintext": return autokeyPlaintextEncrypt(plain, key);
    case "autokey-ciphertext": return autokeyCiphertextEncrypt(plain, key);
  }
}

export function decrypt(cipher: string, key: string, variant: Variant): string {
  switch (variant) {
    case "vigenere": return vigenereDecrypt(cipher, key);
    case "autokey-plaintext": return autokeyPlaintextDecrypt(cipher, key);
    case "autokey-ciphertext": return autokeyCiphertextDecrypt(cipher, key);
  }
}

// 可审计轨迹: 逐位对齐 明文 / 密钥流 / 密文
export function trace(plain: string, key: string, variant: Variant): {
  plain: string;
  keystream: string;
  cipher: string;
} {
  const p = lettersOnly(plain);
  const k = lettersOnly(key);
  let ks: string;
  let cipher: string;
  if (variant === "vigenere") {
    ks = "";
    for (let i = 0; i < p.length; i++) ks += k[i % k.length];
    cipher = vigenereEncrypt(p, k);
  } else if (variant === "autokey-plaintext") {
    ks = (k + p).slice(0, p.length);
    cipher = autokeyPlaintextEncrypt(p, k);
  } else {
    cipher = autokeyCiphertextEncrypt(p, k);
    ks = (k + cipher).slice(0, p.length);
  }
  return { plain: p, keystream: ks, cipher };
}

// ---- 重合指数 (Friedman) ----
export function coincidenceIndex(text: string): number {
  const t = lettersOnly(text);
  const n = t.length;
  if (n < 2) return 0;
  const freq: Record<string, number> = {};
  for (const ch of t) freq[ch] = (freq[ch] || 0) + 1;
  let sum = 0;
  for (const f of Object.values(freq)) sum += f * (f - 1);
  return sum / (n * (n - 1));
}

export function columnIc(text: string, period: number): number {
  const t = lettersOnly(text);
  if (period <= 0) throw new Error("周期必须为正数");
  const cols: string[] = [];
  for (let i = 0; i < period; i++) {
    let col = "";
    for (let j = i; j < t.length; j += period) col += t[j];
    if (col.length >= 2) cols.push(col);
  }
  if (!cols.length) return 0;
  let sum = 0;
  for (const c of cols) sum += coincidenceIndex(c);
  return sum / cols.length;
}
