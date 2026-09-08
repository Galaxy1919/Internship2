"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  decrypt,
  decryptCRT,
  encrypt,
  egcdTrace,
  generateKey,
  keyFromPQ,
  lowExponentAttack,
  millerRabin,
  sign,
  verify,
  type RSAKey,
} from "@/lib/rsa";

const PRESETS = [
  { label: "教材例 p=61 q=53 e=17", p: "61", q: "53", e: "17" },
  { label: "小例 p=17 q=19 e=5", p: "17", q: "19", e: "5" },
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

export default function RsaPage() {
  const [pStr, setPStr] = useState("61");
  const [qStr, setQStr] = useState("53");
  const [eStr, setEStr] = useState("17");
  const [mStr, setMStr] = useState("123");
  const [cipherStr, setCipherStr] = useState("");
  const [sigMsg, setSigMsg] = useState("hello RSA 签名");
  const [sigResult, setSigResult] = useState<bigint | null>(null);
  const [sigTampered, setSigTampered] = useState(false);
  // MR 检测
  const [mrStr, setMrStr] = useState("561");
  const [mrRun, setMrRun] = useState<{ prime: boolean; trace: string[] } | null>(null);
  // e=3 攻击
  const [attack, setAttack] = useState<{ n: bigint; e: bigint; m: bigint; c: bigint; recovered: bigint | null } | null>(null);

  const p = bigintOr(pStr, 61n);
  const q = bigintOr(qStr, 53n);
  const e = bigintOr(eStr, 17n);
  const m = bigintOr(mStr, 123n);

  const keyRec = useMemo<{ key: RSAKey | null; err: string | null }>(() => {
    if (pStr.trim() === "" || qStr.trim() === "" || eStr.trim() === "") return { key: null, err: "请填齐 p、q、e。" };
    if (p === q) return { key: null, err: "p 与 q 不能相等。" };
    if (!millerRabin(p) || !millerRabin(q)) return { key: null, err: "p 或 q 不是素数。" };
    try {
      return { key: keyFromPQ(p, q, e), err: null };
    } catch (ex) {
      return { key: null, err: (ex as Error).message };
    }
  }, [pStr, qStr, eStr, p, q, e]);

  const key = keyRec.key;

  const encryptOut = useMemo(() => {
    if (!key || mStr.trim() === "") return null;
    try {
      return { c: encrypt(m, key.n, key.e) };
    } catch {
      return null;
    }
  }, [key, mStr, m]);

  const decryptPlain = useMemo(() => {
    if (!key || cipherStr.trim() === "") return null;
    const c = bigintOr(cipherStr, 0n);
    try {
      return { naive: decrypt(c, key.n, key.d), crt: decryptCRT(c, key) };
    } catch {
      return null;
    }
  }, [key, cipherStr]);

  const verifyOk = useMemo(() => {
    if (!key || sigResult === null) return null;
    const msg = sigTampered ? sigMsg + "!" : sigMsg;
    return verify(msg, sigResult, key.n, key.e);
  }, [key, sigResult, sigTampered, sigMsg]);

  const runMr = () => {
    const n = bigintOr(mrStr, 561n);
    const trace: string[] = [];
    const prime = millerRabin(n, 8, trace);
    setMrRun({ prime, trace });
  };

  const runAttack = () => {
    try {
      const weak = generateKey(160, 3n); // e=3
      const smallM = 42n;
      const c = encrypt(smallM, weak.n, 3n);
      let recovered: bigint | null = null;
      try {
        recovered = lowExponentAttack(c, 3n);
      } catch {
        recovered = null;
      }
      setAttack({ n: weak.n, e: 3n, m: smallM, c, recovered });
    } catch {
      setAttack(null);
    }
  };

  const egcd = useMemo(() => {
    if (!key) return null;
    try {
      return egcdTrace(key.e, (key.p - 1n) * (key.q - 1n));
    } catch {
      return null;
    }
  }, [key]);

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 12</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">RSA 公钥密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          Rivest–Shamir–Adleman(1977)的安全性建立在大整数分解难题上:公开 n = p·q 却无法还原 p、q。
          {"欧拉定理 m^(φ(n)) ≡ 1 保证 (m^e)^d = m^(ed) ≡ m (mod n)"}。本实现从零写 Miller-Rabin 素性检测,
          并附 <strong style={{ color: "var(--text)" }}>CRT 加速解密</strong>与 <strong style={{ color: "var(--red)" }}>低指数攻击</strong>两个教学演示。
        </p>
      </div>

      {/* 密钥生成 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />
          密钥生成
          <span className="ml-auto font-mono text-xs font-normal" style={{ color: "var(--text-faint)" }}>公钥 (n, e) · 私钥 (n, d)</span>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          <div><label className="field-label">素数 p（保密）</label><input className="input font-mono" value={pStr} onChange={(e) => setPStr(e.target.value)} /></div>
          <div><label className="field-label">素数 q（保密）</label><input className="input font-mono" value={qStr} onChange={(e) => setQStr(e.target.value)} /></div>
          <div><label className="field-label">公钥指数 e（gcd(e, φ)=1）</label><input className="input font-mono" value={eStr} onChange={(e) => setEStr(e.target.value)} /></div>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {PRESETS.map((pr) => (
            <button key={pr.label} className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => { setPStr(pr.p); setQStr(pr.q); setEStr(pr.e); }}>
              {pr.label}
            </button>
          ))}
          <button className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => { const k2 = generateKey(128, 65537n); setPStr(k2.p.toString()); setQStr(k2.q.toString()); setEStr(k2.e.toString()); }}>
            随机 128-bit
          </button>
        </div>
        {keyRec.err && <p className="mt-3 text-sm" style={{ color: "var(--red)" }}>⚠ {keyRec.err}</p>}
        {key && (
          <div className="mt-4 grid gap-2 md:grid-cols-2">
            <div className="kv"><span className="k">模数 n = p·q（公开）</span><span className="v">{key.n.toString()}</span></div>
            <div className="kv"><span className="k">φ(n) = (p−1)(q−1)（保密）</span><span className="v">{((key.p - 1n) * (key.q - 1n)).toString()}</span></div>
            <div className="kv"><span className="k">私钥 d = e⁻¹ mod φ(n)</span><span className="v">{key.d.toString()}</span></div>
            <div className="kv" style={{ borderColor: "rgba(251,191,36,.3)" }}><span className="k">公钥对 (n, e)</span><span className="v">({key.n.toString()}, {key.e.toString()})</span></div>
          </div>
        )}
        {key && egcd && (
          <div className="mt-4">
            <div className="panel-title !text-xs"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />扩展欧几里得求 d = e⁻¹ mod φ(n)（逐步）</div>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr style={{ color: "var(--text-faint)" }}>
                    <th className="pb-2 pr-3 font-medium">步</th>
                    <th className="pb-2 pr-3 font-medium">q</th>
                    <th className="pb-2 pr-3 font-medium">r0</th>
                    <th className="pb-2 pr-3 font-medium">r1</th>
                    <th className="pb-2 pr-3 font-medium">s0</th>
                    <th className="pb-2 font-medium">s1</th>
                  </tr>
                </thead>
                <tbody>
                  {egcd.steps.map((s, i) => (
                    <tr key={i} className="border-t" style={{ borderColor: "var(--border)" }}>
                      <td className="py-1 pr-3" style={{ color: "var(--text-faint)" }}>{i + 1}</td>
                      <td className="py-1 pr-3">{s.q.toString()}</td>
                      <td className="py-1 pr-3">{s.r0.toString()}</td>
                      <td className="py-1 pr-3">{s.r1.toString()}</td>
                      <td className="py-1 pr-3">{s.s0.toString()}</td>
                      <td className="py-1">{s.s1.toString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="hint mt-2">
              末轮 s0 即 d:验证 e·d mod φ(n) = {((key.e * key.d) % ((key.p - 1n) * (key.q - 1n))).toString()}(应为 1),即 d 确为 e 的模逆。
            </p>
          </div>
        )}
      </div>

      {/* 加解密 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />加密（公钥）</div>
          <label className="field-label mt-3">明文整数 m（0 ≤ m &lt; n）</label>
          <div className="flex gap-2">
            <input className="input font-mono" value={mStr} onChange={(e) => setMStr(e.target.value)} />
            {encryptOut && (
              <button className="btn btn-ghost shrink-0 text-xs" onClick={() => setCipherStr(encryptOut.c.toString())}>填入密文框</button>
            )}
          </div>
          {key && !(m >= 0n && m < key.n) && <p className="mt-2 text-sm" style={{ color: "var(--red)" }}>⚠ m 需满足 0 ≤ m &lt; n。</p>}
          {encryptOut && (
            <div className="mt-3">
              <div className="kv"><span className="k">c = m^e mod n</span><span className="v">{encryptOut.c.toString()}</span></div>
              {encryptOut && key && encryptOut.c.toString().length > 60 && <p className="hint mt-1">n 为 {key.n.toString(2).length}-bit,密文长度与 n 相当 —— RSA 不能加密比 n 大的消息,实际用混合加密。</p>}
            </div>
          )}
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />解密与 CRT 加速</div>
          <label className="field-label mt-3">密文 c</label>
          <input className="input font-mono" value={cipherStr} onChange={(e) => setCipherStr(e.target.value)} />
          {decryptPlain && (
            <div className="mt-3 space-y-2">
              <div className="kv"><span className="k">普通解密 m = c^d mod n</span><span className="v">{decryptPlain.naive.toString()}</span></div>
              <div className="kv" style={{ borderColor: "rgba(34,211,238,.3)" }}><span className="k">CRT 加速解密</span><span className="v">{decryptPlain.crt.toString()}</span></div>
              {decryptPlain.naive === decryptPlain.crt && (
                <p className="hint" style={{ color: "var(--cyan)" }}>
                  ✓ 两条路径一致。CRT 把一次大模幂拆成 c^dp mod p 与 c^dq mod q 两次小模幂再合成,实际快约 4 倍。
                </p>
              )}
            </div>
          )}
          {!decryptPlain && <p className="hint mt-3">左侧加密后点「填入密文框」,或直接粘贴密文。</p>}
        </div>
      </div>

      {/* 签名 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />签名与验证</div>
        <p className="hint mt-1">s = H(m)^d mod n（私钥签名）;验证:s^e mod n == H(m)。H 为 SHA-256 摘要截断到 n 长（裸 RSA,无 PSS 填充,仅教学）。</p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[240px] flex-1">
            <label className="field-label">消息</label>
            <input className="input" value={sigMsg} onChange={(e) => setSigMsg(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={() => { if (key) setSigResult(sign(sigMsg, key)); }}>签名</button>
        </div>
        {sigResult !== null && key && (
          <div className="mt-4">
            <div className="kv"><span className="k">签名 s</span><span className="v break-all">{sigResult.toString()}</span></div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button className={`btn !px-3 !py-1 text-xs ${!sigTampered ? "btn-primary" : "btn-ghost"}`} onClick={() => setSigTampered(false)}>验证原消息</button>
              <button className={`btn !px-3 !py-1 text-xs ${sigTampered ? "btn-primary" : "btn-ghost"}`} onClick={() => setSigTampered(true)}>验证被篡改消息</button>
              {verifyOk !== null && <span className={`chip ${verifyOk ? "" : "chip-red"}`}>{verifyOk ? "✓ 签名有效" : "✗ 签名无效（消息被篡改）"}</span>}
            </div>
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Miller-Rabin */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />创新点:Miller-Rabin 素性检测（可审计）</div>
          <p className="hint mt-1">密钥生成的关键:快速判定大数是否为素数。对候选 n 把 n−1 拆成 d·2^r,随机取见证 a 验证 a^d 或逐次平方是否回到 ±1;任一见证失败即合数,误判概率 ≤ 4^−k。</p>
          <div className="mt-3 flex gap-2">
            <input className="input font-mono" value={mrStr} onChange={(e) => setMrStr(e.target.value)} />
            <button className="btn btn-ghost shrink-0" onClick={runMr}>检测</button>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {["561", "3233", "97", "170141183460469231731687303715884105727"].map((x) => (
              <button key={x} className="btn-ghost btn !px-2 !py-0.5 text-[11px] font-mono" onClick={() => setMrStr(x)}>{x.length > 12 ? "2^127−1" : x}</button>
            ))}
          </div>
          {mrRun && (
            <div className="mt-3 rounded-lg border p-3" style={{ borderColor: mrRun.prime ? "rgba(74,222,128,.3)" : "rgba(248,113,113,.3)", background: "rgba(2,6,17,.5)" }}>
              <div className="flex items-center gap-2 text-sm">
                <span className={`chip ${mrRun.prime ? "" : "chip-red"}`}>{mrRun.prime ? "✓ 素数" : "✗ 合数"}</span>
                <span style={{ color: "var(--text-dim)" }}>561 是 Carmichael 数(伪素数),MR 仍能识别。</span>
              </div>
              {mrRun.trace.length > 0 && (
                <pre className="mt-2 overflow-x-auto font-mono text-[11px] leading-relaxed" style={{ color: "var(--text-faint)" }}>{mrRun.trace.join("\n")}</pre>
              )}
            </div>
          )}
        </div>

        {/* 低指数攻击 */}
        <div className="panel p-5" style={{ borderColor: "rgba(248,113,113,.25)" }}>
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />创新点:低指数攻击（e=3,小明文,无填充）</div>
          <p className="hint mt-1 leading-relaxed">
            若 e=3 且明文很小(m³ &lt; n),密文 c = m³ 是<strong style={{ color: "var(--text)" }}>普通整数</strong>而非模幂结果,
            攻击者直接对 c 开立方即可恢复明文 —— 完全不需要私钥。警示:实践必须使用 OAEP/PSS 填充。
          </p>
          <div className="mt-3 flex gap-2">
            <button className="btn" style={{ background: "linear-gradient(180deg,#f87171,#ef4444)", color: "#2a0505" }} onClick={runAttack}>⚡ 生成 e=3 弱密钥并攻击</button>
          </div>
          {attack && (
            <div className="mt-3 space-y-2">
              <div className="kv"><span className="k">弱密钥 n（bits={attack.n.toString(2).length}）</span><span className="v">{attack.n.toString()}</span></div>
              <div className="kv"><span className="k">明文 m（极小）</span><span className="v">{attack.m.toString()}</span></div>
              <div className="kv"><span className="k">密文 c = m³（未模 n）</span><span className="v">{attack.c.toString()}</span></div>
              {attack.recovered !== null ? (
                <>
                  <div className="kv" style={{ borderColor: "rgba(248,113,113,.4)" }}><span className="k">开立方恢复 m′</span><span className="v">{attack.recovered.toString()}</span></div>
                  <p className="text-sm" style={{ color: "var(--red)" }}>⚠ 无需私钥即恢复明文 —— 裸 RSA + 小 e + 小明文不安全。</p>
                </>
              ) : (
                <p className="hint">m³ ≥ n,该攻击不适用 —— 换成更小的明文或更长的 n 再试。</p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />大整数分解难题</div>
          <p className="hint mt-2 leading-relaxed">知道 n 却分解不出 p、q,就无法算 φ(n) 与 d。量子算法(Shor)理论上可破解,因此后量子时代 RSA 正被基于格的方案取代。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />欧拉定理</div>
          <p className="hint mt-2 leading-relaxed">{"m^(φ(n)) ≡ 1 (mod n)"} 是 RSA 正确性的根基:ed ≡ 1 (mod φ(n)) ⇒ m^(ed) = m^(1+k·φ(n)) ≡ m。CRT 只是利用 p、q 加速同一运算。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />填充必不可少</div>
          <p className="hint mt-2 leading-relaxed">裸 RSA 有确定性、低指数、延展性等弱点;现代 RSA 必须用 OAEP(加密)与 PSS(签名)做随机化填充,并保证密钥 ≥ 2048-bit。</p>
        </div>
      </div>
    </div>
  );
}
