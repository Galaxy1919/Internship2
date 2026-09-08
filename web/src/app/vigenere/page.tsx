"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  decrypt,
  encrypt,
  lettersOnly,
  trace,
  coincidenceIndex,
  columnIc,
  type Variant,
} from "@/lib/vigenere";

const VARIANTS: { id: Variant; name: string; desc: string; color: string }[] = [
  { id: "vigenere", name: "Vigenère（密钥周期重复）", desc: "keystream[i] = key[i mod |key|] —— 密钥循环使用", color: "var(--accent)" },
  { id: "autokey-plaintext", name: "Autokey-明文", desc: "keystream = 密钥词 + 明文本身,不再周期", color: "var(--cyan)" },
  { id: "autokey-ciphertext", name: "Autokey-密文", desc: "keystream = 密钥词 + 已生成的密文", color: "var(--violet)" },
];

const EXAMPLES = [
  { label: "Wikipedia Vigenère", variant: "vigenere" as Variant, key: "LEMON", plain: "ATTACK AT DAWN" },
  { label: "Wikipedia Autokey", variant: "autokey-plaintext" as Variant, key: "QUEENLY", plain: "ATTACK AT DAWN" },
  { label: "Autokey-密文", variant: "autokey-ciphertext" as Variant, key: "KEY", plain: "ATTACK" },
];

const IC_NATURAL = 0.0667; // 英文自然语言 IC
const IC_RANDOM = 0.0385; // 完全随机 IC

export default function VigenerePage() {
  const [variant, setVariant] = useState<Variant>("vigenere");
  const [key, setKey] = useState("LEMON");
  const [plain, setPlain] = useState("Attack at dawn");
  const [cipherIn, setCipherIn] = useState("");
  const [scanVariant, setScanVariant] = useState<Variant>("vigenere");

  const active = VARIANTS.find((v) => v.id === variant)!;
  const normKey = useMemo(() => lettersOnly(key), [key]);

  const rec = useMemo(() => {
    if (!normKey) return null;
    try {
      return trace(plain, key, variant);
    } catch {
      return null;
    }
  }, [plain, key, variant, normKey]);

  const dec = useMemo(() => {
    if (!normKey || !cipherIn.trim()) return "";
    try {
      return decrypt(cipherIn, key, variant);
    } catch (e) {
      return `⚠ ${(e as Error).message}`;
    }
  }, [cipherIn, key, variant, normKey]);

  // Friedman 检验扫描: 对长文本密文按周期 p 算平均列 IC
  // 注意文本不能自我重复: 否则 Autokey-明文 的自密钥(接明文)也会带周期, 产生假峰
  const longText = useMemo(
    () =>
      lettersOnly(
        "It was the best of times it was the worst of times it was the age of wisdom it was the age of foolishness it was the epoch of belief it was the epoch of incredulity " +
          "The quick brown fox jumps over the lazy dog while the five boxing wizards jump quickly and pack my box with five dozen liquor jugs " +
          "How much wood would a woodchuck chuck if a woodchuck could chuck wood he would chuck as much wood as a woodchuck would if a woodchuck could chuck wood " +
          "Peter piper picked a peck of pickled peppers a peck of pickled peppers Peter piper picked if Peter piper picked a peck of pickled peppers where is the peck of pickled peppers Peter piper picked " +
          "She sells seashells by the seashore the shells she sells are surely seashells so if she sells shells on the seashore I am sure she sells seashore shells " +
          "To be or not to be that is the question whether it is nobler in the mind to suffer the slings and arrows of outrageous fortune or to take arms against a sea of troubles",
      ),
    [],
  );
  const scan = useMemo(() => {
    const cipher = encrypt(longText, "LEMON", scanVariant);
    const ics = [];
    for (let p = 2; p <= 14; p++) ics.push({ period: p, ic: columnIc(cipher, p) });
    // Friedman 实践: 取第一个明显高于随机水平 (IC_RANDOM+0.014) 的周期;
    // 真实周期的整数倍 (如 10 是 5 的 2 倍) 也会出现高 IC, 首个显著峰值才是密钥长
    const peak = ics.find((x) => x.ic > IC_RANDOM + 0.014) ?? null;
    return { cipher, ics, peak };
  }, [longText, scanVariant]);

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 11</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">多表替代密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          单表替代整篇只换一张表,同频字母同形,易被频率分析攻破;多表替代用<strong style={{ color: "var(--text)" }}>多张替换表轮流加密</strong>,
          同一明文字母在不同位置变成不同密文字母,把频率特征摊平。本页实现任务书要求的三种变体:
          Vigenère、Autokey-明文、Autokey-密文,并内置<strong style={{ color: "var(--text)" }}>Friedman 列重合指数检验</strong>来演示 Vigenère 密钥周期这个致命弱点。
        </p>
      </div>

      {/* 变体切换 */}
      <div className="grid gap-3 sm:grid-cols-3">
        {VARIANTS.map((v) => (
          <button
            key={v.id}
            className="panel p-4 text-left transition hover:-translate-y-0.5"
            onClick={() => setVariant(v.id)}
            style={variant === v.id ? { borderColor: `${v.color}66`, boxShadow: `0 0 20px ${v.color}22` } : undefined}
          >
            <div className="flex items-center gap-2 text-sm font-bold" style={{ color: variant === v.id ? v.color : "var(--text)" }}>
              <span className="h-2 w-2 rounded-full" style={{ background: v.color, boxShadow: `0 0 8px ${v.color}` }} />
              {v.name}
            </div>
            <p className="hint mt-2 leading-relaxed">{v.desc}</p>
          </button>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* 加密 */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: active.color, boxShadow: `0 0 8px ${active.color}` }} />加密</div>
          <label className="field-label mt-3">密钥词（自动忽略非字母、转大写）</label>
          <input className="input font-mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="LEMON" />
          <label className="field-label mt-3">明文</label>
          <textarea className="input min-h-[70px] resize-y" value={plain} onChange={(e) => setPlain(e.target.value)} />
          <div className="mt-2 flex flex-wrap gap-1.5">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                className="btn-ghost btn !px-2.5 !py-1 text-xs"
                onClick={() => { setVariant(ex.variant); setKey(ex.key); setPlain(ex.plain); setCipherIn(""); }}
              >
                {ex.label}
              </button>
            ))}
          </div>

          {rec ? (
            <div className="mt-4">
              <div className="field-label">归一化明文（{rec.plain.length} 字母）</div>
              <div className="output !text-xs break-all" style={{ color: "var(--text)", textShadow: "none" }}>{rec.plain}</div>
              <div className="field-label mt-3">密钥流（每位的移位字母）</div>
              <div className="rounded-lg border px-3 py-2 font-mono text-sm break-all" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)", color: "var(--cyan)" }}>{rec.keystream || "—"}</div>
              <div className="field-label mt-3">密文</div>
              <div className="output break-all">{rec.cipher}</div>
            </div>
          ) : (
            <p className="mt-4 text-sm" style={{ color: "var(--red)" }}>密钥不能为空。</p>
          )}
        </div>

        {/* 逐位轨迹 */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: active.color, boxShadow: `0 0 8px ${active.color}` }} />逐位替换轨迹</div>
          <p className="hint mt-1">明文第 i 位用密钥流第 i 位做 Caesar 移位:密文 = (明文 + 密钥流) mod 26。</p>
          {rec && rec.plain.length > 0 ? (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr style={{ color: "var(--text-faint)" }}>
                    <th className="pb-2 pr-3 font-medium">#</th>
                    <th className="pb-2 pr-3 font-medium">明文</th>
                    <th className="pb-2 pr-3 font-medium">密钥流</th>
                    <th className="pb-2 pr-3 font-medium">移位</th>
                    <th className="pb-2 font-medium">密文</th>
                  </tr>
                </thead>
                <tbody>
                  {rec.plain.split("").slice(0, 60).map((ch, i) => (
                    <tr key={i} className="border-t" style={{ borderColor: "var(--border)" }}>
                      <td className="py-1 pr-3" style={{ color: "var(--text-faint)" }}>{i + 1}</td>
                      <td className="py-1 pr-3 font-bold">{ch}</td>
                      <td className="py-1 pr-3" style={{ color: "var(--cyan)" }}>{rec.keystream[i] ?? "—"}</td>
                      <td className="py-1 pr-3" style={{ color: "var(--text-faint)" }}>+{(rec.keystream[i] ?? "A").charCodeAt(0) - 65}</td>
                      <td className="py-1 font-bold" style={{ color: "var(--accent)" }}>{rec.cipher[i]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {rec.plain.length > 60 && (
                <p className="hint mt-1">仅显示前 60 位,共 {rec.plain.length} 位。</p>
              )}
            </div>
          ) : (
            <p className="hint mt-3">输入明文后显示逐位替换。</p>
          )}
          {rec && (
            <div className="mt-3 kv"><span className="k">密文重合指数 IC</span><span className="v">{coincidenceIndex(rec.cipher).toFixed(4)}</span></div>
          )}
        </div>
      </div>

      {/* 解密 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />
          解密往返验证
        </div>
        <label className="field-label mt-3">输入密文（自动忽略非字母）</label>
        <textarea className="input min-h-[60px] resize-y font-mono" value={cipherIn} onChange={(e) => setCipherIn(e.target.value.toUpperCase())} />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button className="btn btn-ghost text-xs" onClick={() => setCipherIn(rec?.cipher ?? "")}>回填刚才的密文</button>
          {!dec.startsWith("⚠") && dec && <span className="chip chip-violet">✓ 解密成功</span>}
        </div>
        <label className="field-label mt-4">解密结果</label>
        <div className="output break-all" style={dec.startsWith("⚠") ? { color: "var(--red)", textShadow: "none" } : { color: "var(--violet)", textShadow: "0 0 10px rgba(167,139,250,.25)" }}>
          {dec || "等待输入密文…"}
        </div>
        {!dec.startsWith("⚠") && dec && rec && (
          <p className="hint mt-2">✓ 解密还原与归一化明文一致 —— 加解密互为逆过程。</p>
        )}
      </div>

      {/* Friedman 检验 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />
          创新点:Friedman 列重合指数检验 —— 定位 Vigenère 密钥长度
        </div>
        <p className="hint mt-1 leading-relaxed">
          用同一段长文本(密钥 LEMON,长 5)分别生成三种密文,再把密文按周期 p 切成 p 列、求各列平均 IC。
          <strong style={{ color: "var(--text)" }}>若 p 恰好等于真实密钥长度</strong>,每列都是一次 Caesar 移位,保留自然语言分布,
          平均 IC 接近 {IC_NATURAL}(自然语言)且明显高出其它周期;错周期接近 {IC_RANDOM}(随机)。
          Autokey 两变体的密钥不周期重复,任何 p 都测不出峰值 —— Friedman 检验对它们失效,这正是它们相对 Vigenère 的改进。
        </p>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {VARIANTS.map((v) => (
            <button
              key={v.id}
              className={`btn !px-3 !py-1 text-xs ${scanVariant === v.id ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setScanVariant(v.id)}
            >
              {v.name}
            </button>
          ))}
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-[auto_1fr]">
          {/* 柱状图 */}
          <div className="overflow-x-auto">
            <div className="flex items-end gap-1.5" style={{ height: 130 }}>
              {scan.ics.map((x) => {
                const h = Math.max(4, Math.round((x.ic / IC_NATURAL) * 100));
                const isPeak = scan.peak !== null && x.period === scan.peak.period;
                const isMultiplier = scan.peak !== null && x.period > scan.peak.period && x.period % scan.peak.period === 0;
                const hl = isPeak || (isMultiplier && scanVariant === "vigenere");
                return (
                  <div key={x.period} className="flex flex-col items-center justify-end" style={{ width: 30 }}>
                    <span className={`mb-1 font-mono text-[10px] ${hl ? "font-bold" : ""}`} style={{ color: isPeak ? "var(--red)" : hl ? "var(--amber)" : "var(--text-faint)" }}>
                      {x.ic.toFixed(3)}
                    </span>
                    <div
                      className="w-6 rounded-t"
                      style={{
                        height: h,
                        background: isPeak
                          ? "linear-gradient(180deg,#f87171,#ef4444)"
                          : hl
                            ? "linear-gradient(180deg,rgba(251,191,36,.6),rgba(251,191,36,.2))"
                            : "linear-gradient(180deg,rgba(34,211,238,.5),rgba(34,211,238,.15))",
                        boxShadow: isPeak ? "0 0 12px rgba(248,113,113,.4)" : undefined,
                      }}
                    />
                    <span className="mt-1 font-mono text-[10px]" style={{ color: isPeak ? "var(--red)" : hl ? "var(--amber)" : "var(--text-dim)" }}>{x.period}</span>
                  </div>
                );
              })}
            </div>
            <div className="mt-1 text-center font-mono text-[10px]" style={{ color: "var(--text-faint)" }}>周期 2–14（真实密钥长 5）</div>
          </div>
          <div className="flex flex-col justify-center gap-2 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              {scan.peak ? (
                <>
                  <span className="chip" style={{ background: "rgba(248,113,113,.12)", color: "var(--red)", borderColor: "rgba(248,113,113,.4)" }}>
                    首个显著峰值 p = {scan.peak.period}
                  </span>
                  <span className="text-xs" style={{ color: "var(--text-dim)" }}>
                    IC = {scan.peak.ic.toFixed(4)}
                    {scanVariant === "vigenere" ? `（真实密钥长 5;p=10 是 5 的倍数也会偏高 → 取首个峰值即密钥长度）` : "（超过随机阈值的首个周期）"}
                  </span>
                </>
              ) : (
                <span className="chip chip-cyan">无显著峰值（全部接近随机 IC {IC_RANDOM}）</span>
              )}
            </div>
            {scanVariant === "vigenere" ? (
              <p className="hint leading-relaxed" style={{ color: "var(--red)" }}>
                ⚠ 攻击者先扫出真实密钥长度 5,再把密文按 5 列分组,每列分别做 Caesar 频率分析即可还原密钥 —— Vigenère 的周期性是其根本弱点。
              </p>
            ) : (
              <p className="hint leading-relaxed" style={{ color: "var(--accent)" }}>
                ✓ Autokey 的密钥流由消息自身延续,无固定周期,因此列 IC 在所有周期下都接近随机值,频率分析无法直接定位密钥长度。
              </p>
            )}
            <p className="hint">真实密钥长 5(LEMON);自然语言 IC ≈ {IC_NATURAL},随机 IC ≈ {IC_RANDOM}。图中红色柱为首个显著峰值,琥珀色为它的整数倍(周期对齐的伪峰值)。</p>
          </div>
        </div>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />多表轮换</div>
          <p className="hint mt-2 leading-relaxed">同一明文字母因位置不同用不同替换表,密文频率被摊平到接近均匀。但 Vigenère 周期重复使同一字母每 |key| 位重现一次,留下统计痕迹。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />Autokey 自密钥</div>
          <p className="hint mt-2 leading-relaxed">密钥词只作为种子,后续由明文(或密文)自身接续,密钥流无周期。缺点:错误传播(明文变体解密依赖前文)、统计结构更复杂但非不可破。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />走向现代</div>
          <p className="hint mt-2 leading-relaxed">多表替代在 19–20 世纪被广泛使用,但最终被能自动破解周期与密钥的卡西斯基/弗里德曼检验攻破;它直接启发了后来 Shannon 的「混淆与扩散」思想。</p>
        </div>
      </div>
    </div>
  );
}
