"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { aesEncrypt, aesDecrypt, aesRoundStates, aesAvalanche, aesEncryptBlock, pkcs7Pad16 } from "@/lib/aes";
import { strToBytes, bytesToHex, hexToBytes, bytesToStr, keyBytesFromText, bitDiff } from "@/lib/bytes";

const C = "#e879f9";

const EXAMPLES = [
  { key: "example-aes-key!", plain: "0123456789abcdef" },
  { key: "实习密钥", plain: "AES 高级加密标准演示：信息安全实训 2026" },
  { key: "000102030405060708090a0b0c0d0e0f", plain: "Welcome to the AES demo!" },
];

const ROUND_LABELS = ["初始 AddRoundKey", ...Array.from({ length: 9 }, (_, i) => `第 ${i + 1} 轮（含 MixColumns）`), "第 10 轮（无 MixColumns）"];

// 16 字节分组 → 4×4 网格（state 按列优先存储，显示时转为行优先）
function StateGrid({ state, accent }: { state: Uint8Array; accent?: string }) {
  const rows: string[][] = [];
  for (let r = 0; r < 4; r++) {
    const row: string[] = [];
    for (let c = 0; c < 4; c++) row.push(state[4 * c + r].toString(16).padStart(2, "0"));
    rows.push(row);
  }
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 26px)", gap: 2, width: "max-content" }}>
      {rows.flatMap((row, ri) =>
        row.map((hx, ci) => (
          <div
            key={`${ri}-${ci}`}
            className="flex items-center justify-center rounded font-mono text-[10px]"
            style={{
              width: 26,
              height: 26,
              border: `1px solid ${accent ? `${accent}44` : "var(--border)"}`,
              background: accent ? `${accent}0d` : "rgba(2,6,17,.45)",
              color: accent ? accent : "var(--text-dim)",
            }}
          >
            {hx}
          </div>
        ))
      )}
    </div>
  );
}

function toBlock16(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  out.set(bytes.slice(0, 16));
  return out;
}

export default function AesPage() {
  const [plain, setPlain] = useState("AES 高级加密标准演示：信息安全实训 2026");
  const [key, setKey] = useState("实习密钥");
  const [cipherHex, setCipherHex] = useState("");

  // 密钥：32 位 hex 按字节解析；否则 UTF-8 截断/补零到 16 字节
  const key16 = useMemo(() => {
    try {
      return keyBytesFromText(key, 16);
    } catch {
      return null;
    }
  }, [key]);

  const plainBytes = useMemo(() => strToBytes(plain), [plain]);

  const cipher = useMemo(() => {
    if (!key16) return null;
    try {
      return aesEncrypt(plainBytes, key16);
    } catch {
      return null;
    }
  }, [plainBytes, key16]);

  const cipherHexOut = useMemo(() => (cipher ? bytesToHex(cipher) : ""), [cipher]);
  const blockCount = useMemo(() => (cipher ? cipher.length / 16 : 0), [cipher]);

  // 首分组逐轮状态（11 个）：初始 ARK + R1..R10
  const states = useMemo(() => {
    if (!key16) return null;
    try {
      return aesRoundStates(pkcs7Pad16(plainBytes).slice(0, 16), key16);
    } catch {
      return null;
    }
  }, [plainBytes, key16]);

  const deltas = useMemo(() => {
    if (!states) return null;
    return states.map((s, i) => (i === 0 ? 0 : bitDiff(s, states[i - 1])));
  }, [states]);

  const roundtripOk = useMemo(() => {
    if (!cipher || !key16) return false;
    try {
      return bytesToStr(aesDecrypt(cipher, key16)) === plain;
    } catch {
      return false;
    }
  }, [cipher, key16, plain]);

  const decResult = useMemo(() => {
    if (!key16) return { ok: false as const, text: "密钥无效" };
    try {
      if (!cipherHex.trim()) return { ok: true as const, text: "" };
      const c = hexToBytes(cipherHex);
      return { ok: true as const, text: bytesToStr(aesDecrypt(c, key16)) };
    } catch (e) {
      return { ok: false as const, text: (e as Error).message };
    }
  }, [cipherHex, key16]);

  // ---- 雪崩实验：两段明文差 1 字符（默认 A→C 恰为 1 bit 翻转）----
  const [aText, setAText] = useState("AES-Encrypt-Demo");
  const [bText, setBText] = useState("CES-Encrypt-Demo");
  const avalanche = useMemo(() => {
    if (!key16) return null;
    try {
      return aesAvalanche(toBlock16(strToBytes(aText)), toBlock16(strToBytes(bText)), key16);
    } catch {
      return null;
    }
  }, [aText, bText, key16]);

  // ---- 标准向量（FIPS-197 附录 C.1，AES-128）----
  const vector = useMemo(() => {
    const k = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const p = hexToBytes("00112233445566778899aabbccddeeff");
    const mine = bytesToHex(aesEncryptBlock(p, k).ct);
    return { mine, expected: "69c4e0d86a7b0430d8cdb78070b4c55a" };
  }, []);

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: C }}>Lab 08 · 分组密码</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">AES 高级加密标准</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          AES（FIPS 197，前身 Rijndael）是现行对称分组密码标准：<strong style={{ color: "var(--text)" }}>128-bit 分组 + 128/192/256-bit 密钥 + 10/12/14 轮</strong>。
          每轮四步——<span className="mono text-xs" style={{ color: C }}>SubBytes → ShiftRows → MixColumns → AddRoundKey</span>——前三步把单个字节的变化在几轮内扩散到整个分组。
          本页实现 AES-128（10 轮），浏览器端从零编写（含 S-box 查表与 GF(2⁸) 列混合），与 <span className="mono text-xs">Block/AES/main.py</span> 同构。
        </p>
      </div>

      {/* 输入 */}
      <div className="panel p-5">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label">明文（任意文本）</label>
            <textarea
              className="input min-h-[96px] resize-y"
              value={plain}
              onChange={(e) => setPlain(e.target.value)}
              placeholder="输入要加密的文本…"
            />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.key + ex.plain}
                  className="btn-ghost btn !px-2.5 !py-1 text-xs"
                  onClick={() => { setKey(ex.key); setPlain(ex.plain); }}
                >
                  {ex.key.length > 12 ? `${ex.key.slice(0, 10)}…` : ex.key} / {ex.plain.slice(0, 10)}…
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="field-label">密钥（32 位 hex 或任意文本 → 16 字节）</label>
            <input className="input font-mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="example-aes-key! 或 000102…0f" />
            {key16 && (
              <div className="mt-3 space-y-2">
                <div className="kv"><span className="k">实际使用密钥（16 字节 hex）</span><span className="v break-all">{bytesToHex(key16)}</span></div>
                <div className="kv"><span className="k">明文 → PKCS#7 → 分组数</span><span className="v">{plainBytes.length} B → {blockCount} × 16B</span></div>
              </div>
            )}
            <p className="hint mt-2">密钥长度决定轮数：128 bit → 10 轮（本页），192 → 12 轮，256 → 14 轮。这里统一按 AES-128 演示。</p>
          </div>
        </div>
      </div>

      {/* 逐轮状态可视化 */}
      {states && deltas && (
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />扩散过程：首分组 11 个状态</div>
          <p className="hint mt-1">每个 4×4 格子是一个 state（每格 1 字节 hex）。对比相邻两轮的差异比特，能看到前几轮迅速“雪崩”——这正是 AES 扩散性的直观证据。</p>
          <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {states.map((s, i) => (
              <div key={i} className="flex items-start gap-3 rounded-lg border p-3" style={{ borderColor: i === states.length - 1 ? `${C}44` : "var(--border)", background: "rgba(2,6,17,.4)" }}>
                <StateGrid state={s} accent={i === states.length - 1 ? C : undefined} />
                <div className="min-w-0">
                  <div className="text-xs font-semibold" style={{ color: i === states.length - 1 ? C : "var(--text)" }}>{ROUND_LABELS[i]}</div>
                  <div className="mt-1 font-mono text-[11px] break-all" style={{ color: "var(--text-dim)" }}>{bytesToHex(s)}</div>
                  {i > 0 && (
                    <span className="chip mt-1.5" style={{ borderColor: "rgba(251,191,36,.25)", color: "var(--amber)", background: "rgba(251,191,36,.09)" }}>
                      Δ {deltas[i]} bit
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 结果 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />加密结果</div>
          <label className="field-label mt-3">密文（hex）</label>
          <div className="output min-h-[52px] break-all">{cipherHexOut || "—"}</div>
          <p className="hint mt-2">输出恒为 16 的倍数（PKCS#7 填充）。ECB 模式下相同的 16 字节明文分组会得到相同密文分组——观察上面 hex 是否出现重复片段。</p>
          <div className="mt-3 flex items-center gap-2">
            <button className="btn btn-ghost text-xs" onClick={() => setCipherHex(cipherHexOut)}>用此密文去解密</button>
            <span className={`chip ${roundtripOk ? "" : "chip-red"}`}>{roundtripOk ? "✓ 解密还原一致" : "等待输入…"}</span>
          </div>
        </div>

        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />解密（密文 hex → 明文）</div>
          <label className="field-label mt-3">密文（hex 或上方自动回填）</label>
          <textarea
            className="input min-h-[90px] resize-y font-mono"
            value={cipherHex}
            onChange={(e) => setCipherHex(e.target.value)}
            placeholder="粘贴 hex 密文…"
          />
          {!decResult.ok && <p className="mt-2 text-xs" style={{ color: "var(--red)" }}>⚠ {decResult.text}</p>}
          <label className="field-label mt-4">解密明文</label>
          <div className="output min-h-[52px]">{decResult.text || "等待密文…"}</div>
          {decResult.ok && decResult.text && (
            <p className="hint mt-2">
              {decResult.text === plain ? "✓ 解密结果与原文一致" : "（与当前明文字段不同，属正常——解密按密文与密钥独立进行）"}
            </p>
          )}
        </div>
      </div>

      {/* 雪崩实验 */}
      {avalanche && (
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />单比特雪崩实验</div>
          <p className="hint mt-1">两段明文只差一个字符（默认示例首字符 A→C，ASCII 码 0x41→0x43，恰好只翻转 1 bit）。输入更长文本时按各自前 16 字节作为单分组加密。</p>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <label className="field-label">明文 A</label>
              <input className="input font-mono" value={aText} onChange={(e) => setAText(e.target.value)} />
            </div>
            <div>
              <label className="field-label">明文 B（改一个字符）</label>
              <input className="input font-mono" value={bText} onChange={(e) => setBText(e.target.value)} />
            </div>
          </div>
          <div className="mt-3 overflow-x-auto rounded-lg border p-4" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
            <div className="flex items-start gap-2">
              <span className="mt-1.5 w-8 shrink-0 font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>A</span>
              <div className="flex flex-wrap gap-1">
                {Array.from(avalanche.ctA).map((b, i) => {
                  const d = avalanche.ctA[i] !== avalanche.ctB[i];
                  return (
                    <span key={i} className={`byte-diff ${d ? "diff" : "same"}`}>{b.toString(16).padStart(2, "0")}</span>
                  );
                })}
              </div>
            </div>
            <div className="mt-2 flex items-start gap-2">
              <span className="mt-1.5 w-8 shrink-0 font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>B</span>
              <div className="flex flex-wrap gap-1">
                {Array.from(avalanche.ctB).map((b, i) => {
                  const d = avalanche.ctA[i] !== avalanche.ctB[i];
                  return (
                    <span key={i} className={`byte-diff ${d ? "diff" : "same"}`}>{b.toString(16).padStart(2, "0")}</span>
                  );
                })}
              </div>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-1.5">
            <span className="mr-1 font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>逐轮状态差异（bit）：</span>
            {avalanche.changes.map((n, i) => (
              <span
                key={i}
                className="rounded px-1.5 py-0.5 font-mono text-[11px]"
                style={{
                  border: `1px solid ${n > 64 ? "rgba(74,222,128,.4)" : "rgba(251,191,36,.3)"}`,
                  color: n > 64 ? "var(--accent)" : "var(--amber)",
                  background: n > 64 ? "rgba(74,222,128,.08)" : "rgba(251,191,36,.08)",
                }}
                title={ROUND_LABELS[i]}
              >
                R{i}:{n}
              </span>
            ))}
          </div>
          <p className="hint mt-3">
            初始 AddRoundKey 只体现明文的 1 bit 差异；SubBytes 后变成 1 字节的差异，再经 ShiftRows / MixColumns 扩散——到第 2~3 轮即接近 128 bit 的一半。末轮密文约 {Math.round((bitDiff(avalanche.ctA, avalanche.ctB) / 128) * 100)}% 的比特翻转。
          </p>
        </div>
      )}

      {/* 标准向量 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" />FIPS-197 标准向量验证（AES-128）</div>
        <p className="hint mt-1">FIPS-197 附录 C.1：实现正确则下列密文必须逐字节吻合。</p>
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <div className="rounded-lg border p-3" style={{ borderColor: vector.mine === vector.expected ? "rgba(74,222,128,.3)" : "var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs" style={{ color: "var(--text-dim)" }}>key=000102…0f · pt=001122…ff</span>
              {vector.mine === vector.expected ? <span className="chip">✓ 通过</span> : <span className="chip chip-red">✗ 不符</span>}
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>实现</span>
              <span className="break-all font-mono text-xs" style={{ color: vector.mine === vector.expected ? "var(--accent)" : "var(--red)" }}>{vector.mine}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>标准</span>
              <span className="break-all font-mono text-xs" style={{ color: "var(--text-dim)" }}>{vector.expected}</span>
            </div>
          </div>
          <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.35)" }}>
            <div className="text-xs" style={{ color: "var(--text-dim)" }}>向量说明</div>
            <p className="hint mt-2 leading-relaxed">密文差异比例：{vector.mine === vector.expected ? "与标准一致，本实现通过官方向量测试" : "检查实现细节"}。S-box、密钥扩展、列混合任一环节出错都会在首轮后立刻偏离标准输出。</p>
          </div>
        </div>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />轮函数四步</div>
          <p className="hint mt-2 leading-relaxed">SubBytes 用 S-box（GF(2⁸) 逆元 + 仿射变换）逐字节代换；ShiftRows 让第 r 行左移 r 字节、把列间数据打散；MixColumns 把每列按 GF 多项式与固定矩阵相乘、把行间数据混匀；AddRoundKey 与轮密钥异或。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />密钥扩展</div>
          <p className="hint mt-2 leading-relaxed">16 字节主密钥经 RotWord → SubWord → 异或轮常数 RCON 递推成 44 个字，每 4 个字组成一个轮密钥。轮数由密钥长度决定：128/192/256 bit → 10/12/14 轮。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--accent-dim)", boxShadow: "0 0 8px var(--accent-dim)" }} />安全现状</div>
          <p className="hint mt-2 leading-relaxed">AES 是 NIST 现行标准，迄今无实用攻击（侧信道除外）。ECB 模式会泄露分组重复结构，教学演示够用；真实场景应使用 CBC/GCM 加随机 IV。</p>
        </div>
      </div>
    </div>
  );
}
