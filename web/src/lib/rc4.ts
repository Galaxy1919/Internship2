// RC4（Rivest Cipher 4）流密码：KSA 密钥调度 + PRGA 伪随机生成。
// 算法与 stream/RC4/main.py 完全一致，RFC 6229 官方向量自检通过。
// 参考向量：key=0102...10 时，密钥流前 16 字节 = 9ac7cc9a609d1ef7b2932899cde41b97

export interface Rc4Step {
  i: number;
  j: number;
  out: number; // 本步输出的密钥流字节
}

/** KSA：把密钥打散成 0~255 的初始 S 盒。密钥为空时按单字节 0 处理。 */
export function rc4Ksa(key: Uint8Array): Uint8Array {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  const n = key.length || 1;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % n]) & 0xff;
    const t = S[i]; S[i] = S[j]; S[j] = t;
  }
  return S;
}

/** PRGA：从 S 盒生成 n 字节密钥流。会原地修改 S（同一状态只能调用一次）。 */
export function rc4Prga(S: Uint8Array, n: number): Uint8Array {
  const out = new Uint8Array(n);
  let i = 0, j = 0;
  for (let k = 0; k < n; k++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    const t = S[i]; S[i] = S[j]; S[j] = t;
    out[k] = S[(S[i] + S[j]) & 0xff];
  }
  return out;
}

/** 加解密同一函数：明文/密文与密钥流逐字节异或（自反）。 */
export function rc4Crypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  const S = rc4Ksa(key);
  const ks = rc4Prga(S, data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ ks[i];
  return out;
}

/** 仅生成密钥流（不碰数据），供标准向量自检使用。 */
export function rc4Keystream(key: Uint8Array, n: number): Uint8Array {
  return rc4Prga(rc4Ksa(key), n);
}

/** 可视化：KSA 后的完整 S 盒 + PRGA 前 steps 步的 (i, j, 输出) 明细。不修改传入 key。 */
export function rc4Trace(key: Uint8Array, steps: number): { sbox: Uint8Array; steps: Rc4Step[] } {
  const S = rc4Ksa(key);
  const log: Rc4Step[] = [];
  let i = 0, j = 0;
  for (let k = 0; k < steps; k++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    const t = S[i]; S[i] = S[j]; S[j] = t;
    log.push({ i, j, out: S[(S[i] + S[j]) & 0xff] });
  }
  return { sbox: S, steps: log };
}
