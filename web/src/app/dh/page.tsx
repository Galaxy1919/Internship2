"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { exchange, fastPowTrace, tamperDemo } from "@/lib/dh";

const PARAM_PRESETS = [
  { label: "p=23, g=5（教学经典）", p: "23", g: "5", a: "6", b: "15" },
  { label: "p=97, g=5", p: "97", g: "5", a: "35", b: "58" },
  { label: "p=467, g=2", p: "467", g: "2", a: "150", b: "224" },
];

function bigintOr(s: string, fallback: bigint): bigint {
  const t = s.trim();
  if (!t) return fallback;
  try {
    const v = BigInt(t);
    return v >= 0n ? v : fallback;
  } catch {
    return fallback;
  }
}

export default function DhPage() {
  const [pStr, setPStr] = useState("23");
  const [gStr, setGStr] = useState("5");
  const [aStr, setAStr] = useState("6");
  const [bStr, setBStr] = useState("15");
  const [step, setStep] = useState<"a" | "b">("a");
  const [tampered, setTampered] = useState(false);

  const p = bigintOr(pStr, 23n);
  const g = bigintOr(gStr, 5n);

  const rec = useMemo(() => {
    try {
      const aPriv = bigintOr(aStr, 6n);
      const bPriv = bigintOr(bStr, 15n);
      if (aPriv < 2n || aPriv >= p - 1n || bPriv < 2n || bPriv >= p - 1n) return null;
      return exchange(p, g, aPriv, bPriv);
    } catch {
      return null;
    }
  }, [p, g, aStr, bStr]);

  const trace = useMemo(() => {
    if (!rec) return null;
    return step === "a"
      ? fastPowTrace(g, rec.alicePriv, p)
      : fastPowTrace(g, rec.bobPriv, p);
  }, [rec, step, g, p]);

  const tamper = useMemo(() => (rec ? tamperDemo(rec) : null), [rec]);

  const isValid = rec !== null;

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 04</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">Diffie-Hellman 密钥交换</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          Diffie-Hellman（1976）是第一个公钥密码方案：Alice 与 Bob 在不安全的公开信道上，仅凭公开参数与各自的私有值，
          协商出<strong style={{ color: "var(--text)" }}>只有双方知道</strong>的共享密钥。安全性建立在离散对数难题之上——
          即使窃听者拿到全部公开值，也无法在合理时间内还原私钥。
        </p>
      </div>

      {/* 参数设置 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />公开参数与私有值</div>
        <p className="hint mt-1">p 为素数（模数），g 为生成元。p、g 公开；Alice 私钥 a、Bob 私钥 b 各自保密。</p>
        <div className="mt-3 grid gap-3 sm:grid-cols-4">
          <div>
            <label className="field-label">素数 p</label>
            <input className="input font-mono" value={pStr} onChange={(e) => setPStr(e.target.value)} />
          </div>
          <div>
            <label className="field-label">生成元 g</label>
            <input className="input font-mono" value={gStr} onChange={(e) => setGStr(e.target.value)} />
          </div>
          <div>
            <label className="field-label">Alice 私钥 a（保密）</label>
            <input className="input font-mono" value={aStr} onChange={(e) => setAStr(e.target.value)} />
          </div>
          <div>
            <label className="field-label">Bob 私钥 b（保密）</label>
            <input className="input font-mono" value={bStr} onChange={(e) => setBStr(e.target.value)} />
          </div>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {PARAM_PRESETS.map((pr) => (
            <button
              key={pr.label}
              className="btn-ghost btn !px-2.5 !py-1 text-xs"
              onClick={() => { setPStr(pr.p); setGStr(pr.g); setAStr(pr.a); setBStr(pr.b); setTampered(false); }}
            >
              {pr.label}
            </button>
          ))}
        </div>
        {!isValid && (
          <p className="mt-3 text-sm" style={{ color: "var(--red)" }}>
            ⚠ 参数不合法：需要 p 为素数、1 &lt; g &lt; p、私钥满足 2 ≤ a,b ≤ p-2。
          </p>
        )}
      </div>

      {/* 交换流程 */}
      {rec && (
        <>
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_1fr]">
            {/* Alice */}
            <div className="panel p-5">
              <div className="flex items-center gap-2">
                <span className="flex h-8 w-8 items-center justify-center rounded-full font-bold" style={{ background: "rgba(74,222,128,.15)", color: "var(--accent)", border: "1px solid rgba(74,222,128,.35)" }}>A</span>
                <span className="font-bold">Alice</span>
              </div>
              <div className="mt-4 space-y-2 text-sm">
                <div className="kv"><span className="k">私钥 a</span><span className="v">{rec.alicePriv.toString()}</span></div>
                <div className="kv"><span className="k">计算 g^a mod p</span><span className="v">{rec.alicePub.toString()}</span></div>
                <div className="kv" style={{ borderColor: "rgba(74,222,128,.3)" }}>
                  <span className="k">公钥 A → 公开信道</span>
                  <span className="chip">{rec.alicePub.toString()}</span>
                </div>
              </div>
            </div>

            {/* 公开信道 */}
            <div className="flex flex-col items-center justify-center gap-2 px-2 py-6 text-center">
              <div className="rounded-lg border border-dashed px-4 py-3 font-mono text-xs" style={{ borderColor: "var(--border-bright)", background: "rgba(74,222,128,.04)", color: "var(--text-dim)" }}>
                <div className="font-bold" style={{ color: "var(--accent)" }}>公开信道（可被窃听）</div>
                <div className="mt-1.5">p = {rec.p.toString()}</div>
                <div className="mt-1">g = {rec.g.toString()}</div>
                <div className="mt-1.5">
                  A → B：<span className="chip">{rec.alicePub.toString()}</span>
                </div>
                <div className="mt-1">
                  B → A：<span className="chip">{rec.bobPub.toString()}</span>
                </div>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>
                <span>↓</span>
                <span>窃听者 Eve 看到 p, g, A, B</span>
                <span>↓</span>
              </div>
            </div>

            {/* Bob */}
            <div className="panel p-5">
              <div className="flex items-center gap-2">
                <span className="flex h-8 w-8 items-center justify-center rounded-full font-bold" style={{ background: "rgba(34,211,238,.15)", color: "var(--cyan)", border: "1px solid rgba(34,211,238,.35)" }}>B</span>
                <span className="font-bold">Bob</span>
              </div>
              <div className="mt-4 space-y-2 text-sm">
                <div className="kv"><span className="k">私钥 b</span><span className="v">{rec.bobPriv.toString()}</span></div>
                <div className="kv"><span className="k">计算 g^b mod p</span><span className="v">{rec.bobPub.toString()}</span></div>
                <div className="kv" style={{ borderColor: "rgba(34,211,238,.3)" }}>
                  <span className="k">公钥 B → 公开信道</span>
                  <span className="chip chip-cyan">{rec.bobPub.toString()}</span>
                </div>
              </div>
            </div>
          </div>

          {/* 共享密钥 */}
          <div className="panel p-5">
            <div className="panel-title"><span className="dot" style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />共享密钥协商</div>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div className="rounded-lg border p-4" style={{ borderColor: "rgba(74,222,128,.25)", background: "rgba(74,222,128,.04)" }}>
                <div className="text-xs font-semibold" style={{ color: "var(--accent)" }}>Alice 计算</div>
                <div className="mt-2 font-mono text-sm">
                  K = B<sup>a</sup> mod p = {rec.bobPub.toString()}<sup>{rec.alicePriv.toString()}</sup> mod {rec.p.toString()}
                </div>
                <div className="mt-2 output">{rec.aliceSecret.toString()}</div>
              </div>
              <div className="rounded-lg border p-4" style={{ borderColor: "rgba(34,211,238,.25)", background: "rgba(34,211,238,.04)" }}>
                <div className="text-xs font-semibold" style={{ color: "var(--cyan)" }}>Bob 计算</div>
                <div className="mt-2 font-mono text-sm">
                  K = A<sup>b</sup> mod p = {rec.alicePub.toString()}<sup>{rec.bobPriv.toString()}</sup> mod {rec.p.toString()}
                </div>
                <div className="mt-2 output" style={{ color: "var(--cyan)", textShadow: "0 0 10px rgba(34,211,238,.25)" }}>{rec.bobSecret.toString()}</div>
              </div>
            </div>
            {rec.sameSecret && (
              <p className="mt-4 flex items-center gap-2 text-sm" style={{ color: "var(--accent)" }}>
                <span className="chip">✓ 一致</span>
                (g^a)^b = g^(ab) = (g^b)^a —— 模幂运算的交换性保证双方得到相同密钥 K = {rec.aliceSecret.toString()}。
              </p>
            )}
          </div>

          {/* 逐步演算 */}
          <div className="panel p-5">
            <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />快速幂演算（平方-乘）</div>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>查看哪一方的公开值计算过程：</span>
              <button className={`btn !px-3 !py-1 text-xs ${step === "a" ? "btn-primary" : "btn-ghost"}`} onClick={() => setStep("a")}>
                Alice：{rec.alicePub.toString()} = {rec.g.toString()}^{rec.alicePriv.toString()} mod {rec.p.toString()}
              </button>
              <button className={`btn !px-3 !py-1 text-xs ${step === "b" ? "btn-primary" : "btn-ghost"}`} onClick={() => setStep("b")}>
                Bob：{rec.bobPub.toString()} = {rec.g.toString()}^{rec.bobPriv.toString()} mod {rec.p.toString()}
              </button>
            </div>
            {trace && (
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr style={{ color: "var(--text-faint)" }}>
                      <th className="pb-2 pr-4 font-medium">步</th>
                      <th className="pb-2 pr-4 font-medium">剩余指数 e</th>
                      <th className="pb-2 pr-4 font-medium">当前底数 b</th>
                      <th className="pb-2 pr-4 font-medium">e 为奇？</th>
                      <th className="pb-2 font-medium">累乘结果</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trace.steps.map((s, i) => (
                      <tr key={i} className="border-t" style={{ borderColor: "var(--border)" }}>
                        <td className="py-1.5 pr-4" style={{ color: "var(--text-faint)" }}>{i + 1}</td>
                        <td className="py-1.5 pr-4">{s.exponent.toString()}</td>
                        <td className="py-1.5 pr-4">{s.base.toString()}</td>
                        <td className="py-1.5 pr-4">{s.exponent & 1n ? <span className="chip">是 → 乘入结果</span> : <span className="text-xs" style={{ color: "var(--text-faint)" }}>否</span>}</td>
                        <td className="py-1.5">{s.result.toString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="hint mt-2">
                  每轮：若当前指数最低位为 1，则把当前底数乘入结果；随后底数自平方、指数右移一位。复杂度从 O(e) 降到 O(log e)。
                </p>
              </div>
            )}
          </div>

          {/* 篡改演示 */}
          <div className="panel p-5" style={{ borderColor: tampered ? "rgba(248,113,113,.35)" : "var(--border)" }}>
            <div className="panel-title">
              <span className="dot" style={{ background: tampered ? "var(--red)" : "var(--amber)", boxShadow: `0 0 8px ${tampered ? "var(--red)" : "var(--amber)"}` }} />
              中间人篡改演示（主动攻击）
            </div>
            <p className="hint mt-1">模拟 Eve 在信道上把 Alice 的公钥翻转 1 bit 后再转交给 Bob，观察双方密钥是否还能一致。</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <button
                className="btn btn-ghost text-xs"
                onClick={() => setTampered(!tampered)}
              >
                {tampered ? "还原为正常交换" : "模拟篡改公开值"}
              </button>
            </div>
            {tampered && tamper && (
              <div className="mt-4 grid gap-3 md:grid-cols-3">
                <div className="kv"><span className="k">被篡改的 A</span><span className="v">{tamper.fakePub.toString()}</span></div>
                <div className="kv"><span className="k">Bob 按伪造 A 算出的 K'</span><span className="v">{tamper.fakeSecret.toString()}</span></div>
                <div className="kv" style={{ borderColor: "rgba(248,113,113,.4)" }}>
                  <span className="k">与 Alice 的 K 是否一致</span>
                  <span className="chip chip-red">{tamper.same ? "仍一致（罕见）" : "不一致！"}</span>
                </div>
              </div>
            )}
            {tampered && tamper && !tamper.same && (
              <p className="mt-3 text-sm leading-relaxed" style={{ color: "var(--red)" }}>
                ✗ K = {rec.aliceSecret.toString()}，而 K' = {tamper.fakeSecret.toString()}。双方各自算出的密钥不同——
                这说明原始 DH 不提供身份认证，需要结合数字签名（如使用长期公钥）来抵御中间人攻击。
              </p>
            )}
            {!tampered && (
              <p className="hint mt-3">
                正常交换中双方密钥一致。试试「模拟篡改」——如果 Eve 修改了公开值但双方不校验，后续加密通信将因密钥不一致而立即暴露或被利用。
              </p>
            )}
          </div>
        </>
      )}

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />离散对数难题</div>
          <p className="hint mt-2 leading-relaxed">已知 g、p 与 A = g^a mod p，求 a 是困难的（尤其 p 为大素数时）。Eve 看到 A、B 却无法算出 a 或 b。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />模幂交换律</div>
          <p className="hint mt-2 leading-relaxed">(g^a mod p)^b mod p = g^(ab) mod p = (g^b mod p)^a mod p。这个恒等式让双方各自独立算出同一个数。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />局限</div>
          <p className="hint mt-2 leading-relaxed">DH 本身不认证身份，易遭中间人攻击；且仅协商出密钥，不提供加密与签名。实用中通常与 RSA/ECC 数字证书结合。</p>
        </div>
      </div>
    </div>
  );
}
