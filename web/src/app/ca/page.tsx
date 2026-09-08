"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { caCrypt, caKeystream, caEvolution, caRuleBits } from "@/lib/ca";
import { strToBytes, bytesToHex, hexToBytes, bytesToStr, bitDiff, bitRatio } from "@/lib/bytes";

const C = "#a3e635";

const RULES = [
  { n: 30, note: "混沌 · 经典伪随机规则" },
  { n: 90, note: "可加 · Sierpinski 三角" },
  { n: 110, note: "图灵完备 · 通用计算" },
  { n: 150, note: "可加 · 最长序列" },
];

const EXAMPLES = [
  { key: "ca-demo-key", plain: "元胞自动机流密码测试 0123456789" },
  { key: "实习密钥", plain: "CA 流密码演示：信息安全实训 2026" },
];

function BitStrip({ bits, cell = 9, color = C }: { bits: number[]; cell?: number; color?: string }) {
  return (
    <div className="flex gap-px">
      {bits.map((b, i) => (
        <div
          key={i}
          style={{
            width: cell,
            height: cell,
            borderRadius: 1.5,
            background: b ? color : "rgba(2,6,17,.72)",
            border: b ? "none" : "1px solid rgba(148,163,184,.16)",
            boxShadow: b ? `0 0 4px ${color}66` : "none",
          }}
        />
      ))}
    </div>
  );
}

export default function CaPage() {
  const [rule, setRule] = useState(30);
  const [key, setKey] = useState("ca-demo-key");
  const [plain, setPlain] = useState("元胞自动机流密码测试 0123456789");
  const [cipherHex, setCipherHex] = useState("");

  const keyBytes = useMemo(() => strToBytes(key), [key]);
  const plainBytes = useMemo(() => strToBytes(plain), [plain]);
  const n = plainBytes.length;

  const ruleTable = useMemo(() => caRuleBits(rule), [rule]);

  const cipher = useMemo(() => {
    try {
      return caCrypt(plainBytes, keyBytes, rule);
    } catch {
      return null;
    }
  }, [plainBytes, keyBytes, rule]);

  const keystream = useMemo(() => caKeystream(keyBytes, n, rule), [keyBytes, n, rule]);
  const ksHex = useMemo(() => bytesToHex(keystream), [keystream]);
  const cipherHexOut = useMemo(() => (cipher ? bytesToHex(cipher) : ""), [cipher]);

  const cipherText = useMemo(() => {
    if (!cipher) return "";
    const t = bytesToStr(cipher);
    return /^[\x20-\x7e\u4e00-\u9fff\uff00-\uffef，。！？、；：""''（）\s]*$/.test(t) ? t : "";
  }, [cipher]);

  const roundtripOk = useMemo(() => {
    if (!cipher) return false;
    try {
      return bytesToStr(caCrypt(cipher, keyBytes, rule)) === plain;
    } catch {
      return false;
    }
  }, [cipher, keyBytes, rule, plain]);

  // 演化预览：种子行 + 预热后 14 行（每行 64 细胞 → 8 字节）
  const evo = useMemo(() => {
    try {
      return caEvolution(keyBytes, rule, 14);
    } catch {
      return null;
    }
  }, [keyBytes, rule]);

  // 雪崩：密钥最后一个字符翻转 → 密钥流差异
  const avalanche = useMemo(() => {
    if (keyBytes.length === 0) return null;
    const k2 = keyBytes.slice();
    k2[k2.length - 1] ^= 1;
    const a = caKeystream(keyBytes, 32, rule);
    const b = caKeystream(k2, 32, rule);
    return { key2Hex: bytesToHex(k2), diff: bitDiff(a, b), ratio: bitRatio(a, b) };
  }, [keyBytes, rule]);

  // 解密实验
  const decResult = useMemo(() => {
    try {
      if (!cipherHex.trim()) return { ok: true as const, text: "" };
      const c = hexToBytes(cipherHex);
      return { ok: true as const, text: bytesToStr(caCrypt(c, keyBytes, rule)) };
    } catch (e) {
      return { ok: false as const, text: (e as Error).message };
    }
  }, [cipherHex, keyBytes, rule]);

  // ---- 固定输入自检（同 Python selftest）----
  const fixed = useMemo(() => {
    const k1 = strToBytes("ca-demo-key");
    const k2 = strToBytes("ca-demo-Key");
    const p = strToBytes("元胞自动机流密码测试 0123456789");
    const rt = caCrypt(caCrypt(p, k1), k1);
    const round = rt.every((v, i) => v === p[i]);
    const d1 = caKeystream(k1, 64);
    const d2 = caKeystream(k1, 64);
    const det = bytesToHex(d1) === bytesToHex(d2);
    const d3 = caKeystream(k2, 64);
    const diff = bytesToHex(d1) !== bytesToHex(d3);
    return { round, det, diff };
  }, []);

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: C }}>Lab 06 · 流密码</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">CA 元胞自动机流密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          元胞自动机（Cellular Automata）是一维格子：每个细胞只有 0/1 两种状态，按<strong style={{ color: "var(--text)" }}>规则</strong>同步更新——
          新状态只取决于它自己和左右邻居。Rule 30 由单个细胞演化出的图案混沌不可预测，曾被 Mathematica 用作随机数发生器。
          把它当作流密码：密钥经 <span className="mono text-xs">SHA-256</span> 派生为 256 位种子填入 64 个细胞，预热 100 轮后，
          每演化一轮取出 8 字节密钥流与明文异或。算法与 <span className="mono text-xs">stream/CA/main.py</span> 一致。
        </p>
      </div>

      {/* 参数输入 */}
      <div className="panel p-5">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label">演化规则（规则编号决定邻居组合 → 新状态的映射）</label>
            <div className="flex flex-wrap gap-1.5">
              {RULES.map((r) => (
                <button
                  key={r.n}
                  className="btn !px-3 !py-1.5 text-xs"
                  style={
                    rule === r.n
                      ? { background: `linear-gradient(180deg, ${C}, #65a30d)`, color: "#0a0f0a", boxShadow: `0 0 14px ${C}44` }
                      : { border: "1px solid var(--border)", color: "var(--text-dim)" }
                  }
                  onClick={() => setRule(r.n)}
                  title={r.note}
                >
                  Rule {r.n}
                </button>
              ))}
            </div>
            <p className="hint mt-2">当前规则：{RULES.find((r) => r.n === rule)?.note}</p>
          </div>
          <div>
            <label className="field-label">密钥（任意长度文本）</label>
            <input className="input" value={key} onChange={(e) => setKey(e.target.value)} placeholder="如 ca-demo-key…" />
            <div className="mt-3 space-y-2">
              <div className="kv"><span className="k">密钥字节</span><span className="v">{keyBytes.length} B → SHA-256 → 256 bit 种子</span></div>
              <div className="kv"><span className="k">明文长度（= 密钥流长度）</span><span className="v">{n} B</span></div>
            </div>
          </div>
        </div>
        <label className="field-label mt-4">明文</label>
        <textarea
          className="input min-h-[80px] resize-y"
          value={plain}
          onChange={(e) => setPlain(e.target.value)}
          placeholder="输入要加密的文本…"
        />
        <div className="mt-3 flex flex-wrap gap-1.5">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.key + ex.plain}
              className="btn-ghost btn !px-2.5 !py-1 text-xs"
              onClick={() => { setKey(ex.key); setPlain(ex.plain); }}
            >
              {ex.key} / {ex.plain.slice(0, 12)}…
            </button>
          ))}
        </div>
      </div>

      {/* 规则表 + 演化预览 */}
      {evo && (
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />密钥流生成过程可视化</div>
          <div className="mt-3 grid gap-5 lg:grid-cols-[auto_1fr]">
            <div>
              <label className="field-label">Rule {rule} 真值表</label>
              <div className="space-y-1.5">
                {ruleTable.map((t) => (
                  <div key={t.nei} className="flex items-center gap-1.5 font-mono text-[11px]">
                    {t.nei.split("").map((ch, i) => (
                      <span
                        key={i}
                        className="flex h-5 w-5 items-center justify-center rounded"
                        style={{ border: "1px solid var(--border)", color: ch === "1" ? C : "var(--text-dim)", background: ch === "1" ? `${C}14` : "rgba(2,6,17,.4)" }}
                      >
                        {ch}
                      </span>
                    ))}
                    <span style={{ color: "var(--text-faint)" }}>→</span>
                    <span
                      className="flex h-5 w-5 items-center justify-center rounded font-bold"
                      style={{ border: `1px solid ${t.out ? C : "var(--border)"}`, color: t.out ? "#0a0f0a" : "var(--text-dim)", background: t.out ? C : "rgba(2,6,17,.4)" }}
                    >
                      {t.out}
                    </span>
                  </div>
                ))}
              </div>
              <p className="hint mt-2 max-w-[180px]">邻居组合 111→000 对应的输出拼成 8 位二进制，即规则编号。Rule 30 = 00011110₂。</p>
            </div>
            <div className="overflow-x-auto">
              <div className="space-y-1">
                <div className="flex items-center gap-3">
                  <div className="flex w-[210px] shrink-0 items-center gap-2">
                    <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>SHA-256 种子</span>
                  </div>
                  <BitStrip bits={evo.seed} color={C} />
                </div>
                <p className="hint ml-0">↑ 密钥经 SHA-256 派生后的前 64 bit 初始状态（每格 = 1 bit）。接下来预热 100 轮使状态充分扩散，以下是预热后连续 14 轮的演化：</p>
                {evo.rows.map((row, ri) => (
                  <div key={ri} className="flex items-center gap-3">
                    <div className="flex w-[210px] shrink-0 items-center gap-2">
                      <span className="font-mono text-[11px]" style={{ color: ri === 0 ? C : "var(--text-faint)" }}>
                        {ri === 0 ? "预热后第 1 轮" : `第 ${ri + 1} 轮`}
                      </span>
                    </div>
                    <BitStrip bits={row.bits} color={C} />
                    <span className="mono text-[10px]" style={{ color: "var(--text-dim)" }} title="本轮取出的 8 字节密钥流">
                      {bytesToHex(row.bytes)}
                    </span>
                  </div>
                ))}
              </div>
              <p className="hint mt-2">每轮从 64 细胞按 8 bit 一组拼出 8 字节 —— 右侧 hex 即该轮密钥流；加密用的密钥流就是按明文长度截取这些字节。</p>
            </div>
          </div>
        </div>
      )}

      {/* 加解密结果 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />加密结果</div>
          <label className="field-label mt-3">密钥流（hex，与明文等长）</label>
          <div className="output min-h-[52px] break-all">{ksHex || "—"}</div>
          {cipherText ? (
            <>
              <label className="field-label mt-4">密文（文本形式）</label>
              <div className="output min-h-[52px]">{cipherText}</div>
            </>
          ) : (
            <p className="hint mt-3">密文含不可打印字节，请用下方 hex 形式查看或粘贴到右侧解密。</p>
          )}
          <label className="field-label mt-4">密文（hex）</label>
          <div className="output min-h-[52px] break-all">{cipherHexOut || "—"}</div>
          <div className="mt-3 flex items-center gap-2">
            <button className="btn btn-ghost text-xs" onClick={() => setCipherHex(cipherHexOut)}>用此密文去解密</button>
            <span className={`chip ${roundtripOk ? "" : "chip-red"}`}>
              {roundtripOk ? "✓ 加解密往返一致" : "等待输入…"}
            </span>
          </div>
        </div>

        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />解密（密文 hex → 明文）</div>
          <p className="hint mt-1">与 RC4 同理：解密就是再异或一次同一密钥流。</p>
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

      {/* 自检 + 雪崩 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" />性质自检与雪崩效应</div>
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          <div className="rounded-lg border p-3" style={{ borderColor: fixed.round ? "rgba(74,222,128,.3)" : "var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>加解密往返一致</span>
              {fixed.round ? <span className="chip">✓ PASS</span> : <span className="chip chip-red">✗ FAIL</span>}
            </div>
            <p className="hint mt-2">同一密钥加密后再解密，能逐字节还原明文。</p>
          </div>
          <div className="rounded-lg border p-3" style={{ borderColor: fixed.det ? "rgba(74,222,128,.3)" : "var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>同密钥密钥流确定</span>
              {fixed.det ? <span className="chip">✓ PASS</span> : <span className="chip chip-red">✗ FAIL</span>}
            </div>
            <p className="hint mt-2">同一密钥两次生成 64 字节密钥流，逐字节相同（确定性）。</p>
          </div>
          <div className="rounded-lg border p-3" style={{ borderColor: fixed.diff ? "rgba(74,222,128,.3)" : "var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>不同密钥密钥流不同</span>
              {fixed.diff ? <span className="chip">✓ PASS</span> : <span className="chip chip-red">✗ FAIL</span>}
            </div>
            <p className="hint mt-2">ca-demo-key 与 ca-demo-Key 只差一个字母，密钥流截然不同。</p>
          </div>
        </div>
        {avalanche && (
          <div className="mt-4 border-t pt-4" style={{ borderColor: "var(--border)" }}>
            <p className="hint">
              把当前密钥最后一个字节翻转（{keyBytes.length ? bytesToHex(keyBytes.slice(-1)) : "—"} → {avalanche.key2Hex.slice(-2)}），
              前 32 字节密钥流的变化：
            </p>
            <div className="mt-3 grid gap-3 sm:grid-cols-3">
              <div className="kv"><span className="k">差异比特</span><span className="v">{avalanche.diff} / 256</span></div>
              <div className="kv"><span className="k">差异比例</span><span className="v">{(avalanche.ratio * 100).toFixed(1)}%</span></div>
              <div className="kv">
                <span className="k">结论</span>
                <span className="v" style={{ color: avalanche.ratio > 0.35 && avalanche.ratio < 0.65 ? "var(--accent)" : "var(--amber)" }}>
                  {avalanche.ratio > 0.35 && avalanche.ratio < 0.65 ? "✓ 接近 50% 理想雪崩" : "观察中"}
                </span>
              </div>
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full" style={{ background: "rgba(2,6,17,.8)", border: "1px solid var(--border)" }}>
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${Math.max(4, Math.min(100, avalanche.ratio * 100))}%`, background: "linear-gradient(90deg,#4ade80,#fbbf24,#f87171)" }}
              />
            </div>
          </div>
        )}
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />规则编号即演化法则</div>
          <p className="hint mt-2 leading-relaxed">8 种邻居组合（111…000）各指定一个 0/1 输出，拼成 8 位二进制即规则号。Rule 30 处于“混沌边缘”，既不完全随机也不快速周期化——伪随机性的理想区间。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />SHA-256 密钥派生</div>
          <p className="hint mt-2 leading-relaxed">短密钥直接展开会产生强相关的初始模式（只差一个字符的密钥可能得到相同状态）。先用 SHA-256 打散成 256 位再填细胞——与 RC4 里 KSA 的角色相同，都是“密钥 → 初始状态”。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />预热与环形边界</div>
          <p className="hint mt-2 leading-relaxed">演化前 100 轮预热，消除初始状态的简单模式；最左与最右细胞互为邻居（环形），避免边界效应。CA 流密码是研究热点，但实用场景仍以 AES-CTR / ChaCha20 为主。</p>
        </div>
      </div>
    </div>
  );
}
