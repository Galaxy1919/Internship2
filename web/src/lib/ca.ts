// CA（Cellular Automata，一维元胞自动机）流密码。
// 算法与 stream/CA/main.py 一致：SHA-256 密钥派生 → 64 细胞初始态 → 预热 100 轮 →
// 每演化一轮取出 8 字节密钥流 → 明文 XOR 密钥流。
// 默认 Rule 30（混沌伪随机经典规则），可换 90 / 110 / 150。

import { sha256 } from "./sha256";

export const DEFAULT_CELLS = 64;
export const WARMUP_STEPS = 100;

/** 规则编号 → 8 位查表：table[0..7] 依次对应邻居组合 111,110,...,000 的输出。 */
export function buildRuleTable(rule: number): number[] {
  const t: number[] = [];
  for (let i = 0; i < 8; i++) t.push((rule >> (7 - i)) & 1);
  return t;
}

/** 供可视化：每条邻居组合 (111..000) 及该规则下的新状态。 */
export function caRuleBits(rule: number): { nei: string; out: number }[] {
  const t = buildRuleTable(rule);
  return t.map((out, i) => ({
    nei: (7 - i).toString(2).padStart(3, "0"),
    out,
  }));
}

/** 密钥 → 初始细胞：SHA-256 打散成 256 位种子后按位循环填充。 */
export function keyToSeedCells(key: Uint8Array, cells: number = DEFAULT_CELLS): number[] {
  const seed = sha256(key);
  const bits: number[] = [];
  for (const b of seed) {
    for (let sh = 7; sh >= 0; sh--) bits.push((b >> sh) & 1);
  }
  const out: number[] = [];
  for (let i = 0; i < cells; i++) out.push(bits[i % bits.length]);
  return out;
}

/** 演化一轮：新状态 = f(左邻居, 自己, 右邻居)，环形边界。 */
export function caStep(cells: number[], table: number[]): number[] {
  const n = cells.length;
  const next = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) {
    const left = cells[(i - 1 + n) % n];
    const center = cells[i];
    const right = cells[(i + 1) % n];
    next[i] = table[(left << 2) | (center << 1) | right];
  }
  return next;
}

/** 由密钥生成 nBytes 字节密钥流。 */
export function caKeystream(
  key: Uint8Array,
  nBytes: number,
  rule: number = 30,
  cells: number = DEFAULT_CELLS,
  warmup: number = WARMUP_STEPS
): Uint8Array {
  const table = buildRuleTable(rule);
  let state = keyToSeedCells(key, cells);
  for (let i = 0; i < warmup; i++) state = caStep(state, table);
  const out = new Uint8Array(nBytes);
  let got = 0;
  while (got < nBytes) {
    state = caStep(state, table);
    for (let b = 0; b < cells / 8 && got < nBytes; b++) {
      let v = 0;
      for (let k = 0; k < 8; k++) v = (v << 1) | state[b * 8 + k];
      out[got++] = v;
    }
  }
  return out;
}

/** 加解密同一函数：与密钥流逐字节异或。 */
export function caCrypt(data: Uint8Array, key: Uint8Array, rule: number = 30): Uint8Array {
  const ks = caKeystream(key, data.length, rule);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ ks[i];
  return out;
}

export interface CaRow {
  bits: number[]; // cells 个细胞的 0/1
  bytes: Uint8Array; // 该行演化后取出的 cells/8 字节
}

/** 可视化：预热结束后继续演化 rows 行，返回每一行的细胞态与该行产出的字节。 */
export function caEvolution(
  key: Uint8Array,
  rule: number = 30,
  rows: number = 12,
  cells: number = DEFAULT_CELLS,
  warmup: number = WARMUP_STEPS
): { seed: number[]; rows: CaRow[] } {
  const table = buildRuleTable(rule);
  let state = keyToSeedCells(key, cells);
  for (let i = 0; i < warmup; i++) state = caStep(state, table);
  const out: CaRow[] = [];
  for (let r = 0; r < rows; r++) {
    state = caStep(state, table);
    const bytes = new Uint8Array(cells / 8);
    for (let b = 0; b < cells / 8; b++) {
      let v = 0;
      for (let k = 0; k < 8; k++) v = (v << 1) | state[b * 8 + k];
      bytes[b] = v;
    }
    out.push({ bits: state.slice(), bytes });
  }
  return { seed: keyToSeedCells(key, cells), rows: out };
}
