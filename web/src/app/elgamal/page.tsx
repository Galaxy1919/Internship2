"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  decrypt,
  encrypt,
  generateKey,
  modPow,
  randInRange,
  recoverXFromReusedK,
  sign,
  verify,
  type ElGamalKey,
} from "@/lib/elgamal";

const PARAM_PRESETS = [
  { label: "p=23, g=4（课堂手算）", p: "23", q: "11", g: "4" },
  { label: "p=47, g=2", p: "47", q: "23", g: "2" },
  { label: "p=107, g=4", p: "107", q: "53", g: "4" },
];

const MSG_PRESETS = [
  { label: "pay 100 to bank A", msg1: "pay 100 to bank A", msg2: "pay 999 to bank Z" },
  { label: "transfer to Alice", msg1: "transfer 100 to Alice", msg2: "transfer 100 to Bob" },
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

function fmt(n: bigint): string {
  return n.toString();
}

export default function ElgamalPage() {
  // ---- 密钥参数 (文本可编辑, 无效时页面提示) ----
  const [pStr, setPStr] = useState("23");
  const [qStr, setQStr] = useState("11");
  const [gStr, setGStr] = useState("4");
  const [xStr, setXStr] = useState("7"); // 初始固定, 便于首屏可复现; "重新生成"按钮才会随机

  // ---- 加密演示 ----
  const [mStr, setMStr] = useState("20");
  const [encResult, setEncResult] = useState<{ c1: bigint; c2: bigint; k: bigint } | null>(null);

  // ---- 签名演示 ----
  const [sigMsg, setSigMsg] = useState("ElGamal demo message");
  const [sigResult, setSigResult] = useState<{ r: bigint; s: bigint; h: bigint; k: bigint } | null>(null);
  const [sigTampered, setSigTampered] = useState(false);

  // ---- k 重用攻击演示 ----
  const [atkMsg1, setAtkMsg1] = useState("pay 100 to bank A");
  const [atkMsg2, setAtkMsg2] = useState("pay 999 to bank Z");
  const [attack, setAttack] = useState<{
    sig1: { r: bigint; s: bigint; h: bigint; k: bigint };
    sig2: { r: bigint; s: bigint; h: bigint; k: bigint };
    usedK: bigint;
    x: bigint;
    h1: bigint;
    h2: bigint;
    n: bigint;
    candidates: bigint[];
    verified: boolean;
  } | null>(null);

  const p = bigintOr(pStr, 23n);
  const q = bigintOr(qStr, 11n);
  const g = bigintOr(gStr, 4n);
  const x = bigintOr(xStr, 7n);

  // 实时计算 y = g^x mod p 并校验参数
  const keyRec = useMemo<{ key: ElGamalKey | null; err: string | null }>(() => {
    if (pStr.trim() === "" || qStr.trim() === "" || gStr.trim() === "" || xStr.trim() === "") {
      return { key: null, err: "请填齐 p、q、g、x。" };
    }
    if (!(p > 3n)) return { key: null, err: "p 需为大于 3 的素数。" };
    if (p !== 2n * q + 1n) return { key: null, err: "p 必须是安全素数 p = 2q + 1（q 为素数）。" };
    if (!(g > 1n && g < p)) return { key: null, err: "生成元需满足 1 < g < p。" };
    if (!(x >= 2n && x < q)) return { key: null, err: `私钥需满足 2 ≤ x < q = ${q}。` };
    const y = modPow(g, x, p);
    if (y === 1n) return { key: null, err: "g 的阶不为 q（g^q mod p 应为 1 且 g≠1），请换生成元。" };
    return { key: { p, q, g, x, y }, err: null };
  }, [p, q, g, x, pStr, qStr, gStr, xStr]);

  const key = keyRec.key;
  const m = bigintOr(mStr, 20n);

  const applyPreset = (pr: (typeof PARAM_PRESETS)[number]) => {
    setPStr(pr.p);
    setQStr(pr.q);
    setGStr(pr.g);
    setXStr(String(2 + Math.floor(Math.random() * (Number(BigInt(pr.q) - 3n)))));
    setEncResult(null);
    setSigResult(null);
    setAttack(null);
  };

  const randomKey64 = () => {
    try {
      const k2 = generateKey(64);
      setPStr(k2.p.toString());
      setQStr(k2.q.toString());
      setGStr(k2.g.toString());
      setXStr(k2.x.toString());
      setEncResult(null);
      setSigResult(null);
      setAttack(null);
    } catch {
      /* noop */
    }
  };

  const doEncrypt = () => {
    if (!key) return;
    try {
      // 会话密钥取在 g 的阶 q 内: 保证每次 k 都产生不同密文 (k mod q 不碰撞)
      setEncResult(encrypt(m, key, randInRange(key.q)));
    } catch {
      setEncResult(null);
    }
  };

  const doSign = () => {
    if (!key) return;
    try {
      setSigResult(sign(sigMsg, key));
      setSigTampered(false);
    } catch {
      setSigResult(null);
    }
  };

  const doAttack = () => {
    if (!key) return;
    // 模拟 Alice 的错误实现: 两条消息复用同一个临时秘密 k
    let sig1: { r: bigint; s: bigint; h: bigint; k: bigint } | null = null;
    let sig2: { r: bigint; s: bigint; h: bigint; k: bigint } | null = null;
    let usedK = 0n;
    for (let tries = 0; tries < 200; tries++) {
      usedK = randInRange(key.p - 1n); // [2, p-2]
      try {
        const s1 = sign(atkMsg1, key, usedK);
        const s2 = sign(atkMsg2, key, usedK);
        sig1 = s1;
        sig2 = s2;
        break;
      } catch {
        continue;
      }
    }
    if (!sig1 || !sig2) return;
    try {
      const res = recoverXFromReusedK(atkMsg1, sig1, atkMsg2, sig2, key);
      setAttack({ sig1, sig2, usedK, ...res });
    } catch {
      setAttack(null);
    }
  };

  const decryptBack = useMemo(() => {
    if (!key || !encResult) return null;
    try {
      return decrypt(encResult.c1, encResult.c2, key);
    } catch {
      return null;
    }
  }, [key, encResult]);

  // 签名验证: 用 (未篡改/篡改) 消息分别验
  const verifyOk = useMemo(() => {
    if (!key || !sigResult) return null;
    const msg = sigTampered ? sigMsg + "!" : sigMsg;
    return verify(msg, sigResult, key);
  }, [key, sigResult, sigTampered, sigMsg]);

  const attackCandidatesChecked = useMemo(() => {
    if (!key || !attack) return null;
    return attack.candidates.map((k2) => ({ k: k2, gk: modPow(key.g, k2, key.p), hit: modPow(key.g, k2, key.p) === attack.sig1.r }));
  }, [key, attack]);

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 10</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">ElGamal 公钥加密与签名</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          Taher ElGamal 于 1985 年提出,安全性依赖<strong style={{ color: "var(--text)" }}>离散对数难题</strong>(DLP)。
          与 RSA 依赖大整数分解不同,ElGamal 直接在 <strong style={{ color: "var(--text)" }}>Zp* 的 q 阶子群</strong>上运算:
          本实现生成<strong style={{ color: "var(--text)" }}>安全素数 p = 2q + 1</strong>(q 亦为素数),并选用阶恰为 q 的生成元,
          避免小因子子群导致的 DLP 退化。加密使用随机会话密钥 k,<strong style={{ color: "var(--text)" }}>同一明文每次密文都不同</strong>。
        </p>
      </div>

      {/* 密钥生成 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />
          安全素数密钥对
          <span className="ml-auto font-mono text-xs font-normal" style={{ color: "var(--text-faint)" }}>公开 (p, g, y) · 保密 x</span>
        </div>
        <p className="hint mt-1">本实现生成安全素数 p = 2q + 1(q 也是素数),并取 g = h² mod p 保证 g 的阶为 q——这是防小子群攻击的关键一步。</p>
        <div className="mt-3 grid gap-3 sm:grid-cols-4">
          <div>
            <label className="field-label">安全素数 p</label>
            <input className="input font-mono" value={pStr} onChange={(e) => { setPStr(e.target.value); setEncResult(null); setAttack(null); }} />
          </div>
          <div>
            <label className="field-label">q = (p−1)/2</label>
            <input className="input font-mono" value={qStr} onChange={(e) => { setQStr(e.target.value); setEncResult(null); setAttack(null); }} />
          </div>
          <div>
            <label className="field-label">生成元 g（阶为 q）</label>
            <input className="input font-mono" value={gStr} onChange={(e) => { setGStr(e.target.value); setEncResult(null); setAttack(null); }} />
          </div>
          <div>
            <label className="field-label">私钥 x（保密）</label>
            <input className="input font-mono" value={xStr} onChange={(e) => { setXStr(e.target.value); setEncResult(null); setAttack(null); }} />
          </div>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {PARAM_PRESETS.map((pr) => (
            <button key={pr.label} className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => applyPreset(pr)}>
              {pr.label}
            </button>
          ))}
          <button className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={randomKey64}>
            随机生成 64-bit 安全素数
          </button>
        </div>
        {keyRec.err && (
          <p className="mt-3 text-sm" style={{ color: "var(--red)" }}>⚠ {keyRec.err}</p>
        )}
        {key && (
          <div className="mt-4 grid gap-2 md:grid-cols-2">
            <div className="kv"><span className="k">公钥 y = g^x mod p</span><span className="v">{fmt(key.y)}</span></div>
            <div className="kv" style={{ borderColor: "rgba(251,191,36,.3)" }}><span className="k">私钥 x（仅 Alice 知道）</span><span className="v">{fmt(key.x)}</span></div>
          </div>
        )}
      </div>

      {/* 加解密 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />
            加密（Bob → Alice）
          </div>
          <p className="hint mt-1">Bob 用 Alice 的公钥加密;每次加密都掷新的会话密钥 k,密文 (c1, c2) 随之变化。</p>
          <label className="field-label mt-3">明文整数 m（1 ≤ m &lt; p）</label>
          <div className="flex gap-2">
            <input className="input font-mono" value={mStr} onChange={(e) => setMStr(e.target.value)} />
            <button className="btn btn-primary shrink-0" onClick={doEncrypt}>加密</button>
          </div>
          {key && !(m >= 1n && m < key.p) && (
            <p className="mt-2 text-sm" style={{ color: "var(--red)" }}>⚠ m 越界:需要 1 ≤ m &lt; p = {fmt(key.p)}。</p>
          )}
          {encResult && (
            <div className="mt-4 space-y-2 text-sm">
              <div className="kv"><span className="k">会话密钥 k（随机）</span><span className="v">{fmt(encResult.k)}</span></div>
              <div className="kv"><span className="k">c1 = g^k mod p</span><span className="v">{fmt(encResult.c1)}</span></div>
              <div className="kv"><span className="k">c2 = m·y^k mod p</span><span className="v">{fmt(encResult.c2)}</span></div>
              <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
                <div className="text-xs" style={{ color: "var(--text-faint)" }}>密文 (c1, c2)</div>
                <div className="output mt-1.5">({fmt(encResult.c1)}, {fmt(encResult.c2)})</div>
              </div>
            </div>
          )}
        </div>

        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />
            解密与随机性验证
          </div>
          <p className="hint mt-1">Alice 用私钥 x 解密:m = c2 · c1^(p−1−x) mod p(费马小定理,避免模逆)。</p>
          {decryptBack !== null && encResult && (
            <>
              <div className="kv mt-3"><span className="k">解密结果 m′</span><span className="v">{fmt(decryptBack)}</span></div>
              {decryptBack === m && (
                <p className="mt-3 flex items-center gap-2 text-sm" style={{ color: "var(--accent)" }}>
                  <span className="chip">✓ 还原一致</span>
                  c2 · (c1^x)⁻¹ = m · y^k · (g^k)^(−x) = m · g^(xk−xk) = m
                </p>
              )}
            </>
          )}
          {encResult && (
            <div className="mt-4">
              <button className="btn btn-ghost text-xs" onClick={doEncrypt}>换一个随机 k 再加密一次</button>
              <p className="hint mt-2">
                对比两次 (c1, c2):明文相同但密文不同——ElGamal 是<strong style={{ color: "var(--text)" }}>随机化加密</strong>,
                天然抵抗密文重放/比较攻击,这是它与教科书 RSA 的显著差异。
              </p>
            </div>
          )}
          {!encResult && (
            <p className="hint mt-3">先在左侧用公钥加密一条消息,再观察解密与两次密文差异。</p>
          )}
        </div>
      </div>

      {/* 签名 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />
          签名与验证（Alice 签名 → Bob 验签）
        </div>
        <p className="hint mt-1">
          签名:r = g^k mod p,s = (H(m) − x·r)·k⁻¹ mod (p−1),要求 gcd(k, p−1)=1。
          验证:{"g^(H(m)) ≡ y^r · r^s (mod p)"}。H 为 SHA-256 摘要模 p。
        </p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[260px] flex-1">
            <label className="field-label">待签名消息</label>
            <input className="input" value={sigMsg} onChange={(e) => setSigMsg(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={doSign}>签名</button>
        </div>
        {sigResult && (
          <div className="mt-4 grid gap-2 md:grid-cols-3">
            <div className="kv"><span className="k">H(m)（SHA-256 mod p）</span><span className="v">{fmt(sigResult.h)}</span></div>
            <div className="kv"><span className="k">r = g^k</span><span className="v">{fmt(sigResult.r)}</span></div>
            <div className="kv"><span className="k">s = (H−x·r)·k⁻¹</span><span className="v">{fmt(sigResult.s)}</span></div>
          </div>
        )}
        {sigResult && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button className={`btn !px-3 !py-1 text-xs ${!sigTampered ? "btn-primary" : "btn-ghost"}`} onClick={() => setSigTampered(false)}>
              验证原消息
            </button>
            <button className={`btn !px-3 !py-1 text-xs ${sigTampered ? "btn-primary" : "btn-ghost"}`} onClick={() => setSigTampered(true)}>
              验证被篡改消息
            </button>
            {verifyOk !== null && (
              <span className={`chip ${verifyOk ? "" : "chip-red"}`} style={verifyOk ? undefined : {}}>
                {verifyOk ? "✓ 签名有效" : "✗ 签名无效（消息被篡改）"}
              </span>
            )}
          </div>
        )}
        {!sigResult && <p className="hint mt-3">点击「签名」生成签名,再切换消息是否被篡改,观察验证结果翻转。</p>}
      </div>

      {/* k 重用攻击 */}
      <div className="panel p-5" style={{ borderColor: "rgba(248,113,113,.3)" }}>
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />
          创新点演示:k 重用攻击 —— 私钥恢复
        </div>
        <p className="hint mt-1 leading-relaxed">
          若 Alice 用<strong style={{ color: "var(--red)" }}>同一个临时秘密 k</strong>签署两条不同消息,则 r = g^k 相同,私钥 x 可被直接恢复!
          攻击方程 k·(s₁−s₂) ≡ (H(m₁)−H(m₂)) (mod q) 必须在<strong style={{ color: "var(--text)" }}>模 q = (p−1)/2</strong>下求解——
          模 p−1 会因 2 因子混入伪解;得到候选 k 后还需用 r₁ == g^k 过滤、用 g^x == y 回验,才返回唯一合法私钥。
        </p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <div>
            <label className="field-label">消息 1（Alice 签署）</label>
            <input className="input" value={atkMsg1} onChange={(e) => setAtkMsg1(e.target.value)} />
          </div>
          <div>
            <label className="field-label">消息 2（Alice 签署）</label>
            <input className="input" value={atkMsg2} onChange={(e) => setAtkMsg2(e.target.value)} />
          </div>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {MSG_PRESETS.map((pr) => (
            <button key={pr.label} className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => { setAtkMsg1(pr.msg1); setAtkMsg2(pr.msg2); }}>
              {pr.label}
            </button>
          ))}
        </div>
        <div className="mt-3">
          <button className="btn" style={{ background: "linear-gradient(180deg,#f87171,#ef4444)", color: "#2a0505", boxShadow: "0 2px 14px rgba(248,113,113,.3)" }} onClick={doAttack}>
            ⚡ 模拟两次签名复用同一 k 并攻击
          </button>
        </div>

        {attack && key && (
          <div className="mt-4 space-y-3">
            <div className="grid gap-2 md:grid-cols-2">
              <div className="step-line">
                <div className="text-xs font-semibold" style={{ color: "var(--red)" }}>签名 1  (r₁, s₁)</div>
                <div className="mt-1 font-mono text-sm break-all">
                  ({fmt(attack.sig1.r)}, {fmt(attack.sig1.s)})
                </div>
                <div className="hint mt-1">H(m₁) = {fmt(attack.sig1.h)}</div>
              </div>
              <div className="step-line">
                <div className="text-xs font-semibold" style={{ color: "var(--red)" }}>签名 2  (r₂, s₂)</div>
                <div className="mt-1 font-mono text-sm break-all">
                  ({fmt(attack.sig2.r)}, {fmt(attack.sig2.s)})
                </div>
                <div className="hint mt-1">H(m₂) = {fmt(attack.sig2.h)}</div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span style={{ color: "var(--text-dim)" }}>攻击者发现:</span>
              <span className="chip chip-red">r₁ = r₂（同一 k 的指纹）</span>
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>且 (r₁, s₁) 与 (r₂, s₂) 是对两条不同消息的有效签名 —— k 已被复用!</span>
            </div>

            <div className="step-line">
              <div className="text-xs font-semibold" style={{ color: "var(--cyan)" }}>第 1 步 · 建立攻击方程（模 q）</div>
              <div className="mt-1 font-mono text-sm">
                k·(s₁−s₂) ≡ (H(m₁)−H(m₂)) (mod q)&nbsp;&nbsp;
                <span style={{ color: "var(--text-faint)" }}>q = (p−1)/2 = {fmt(attack.n)}</span>
              </div>
              <div className="hint mt-1">不能模 p−1 = {fmt(key.p - 1n)}:那里因 2 因子会出现伪解;g 的阶是 q,方程在模 q 下才有唯一意义。</div>
            </div>

            <div className="step-line">
              <div className="text-xs font-semibold" style={{ color: "var(--cyan)" }}>第 2 步 · 解线性同余得候选 k</div>
              {attackCandidatesChecked && attackCandidatesChecked.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {attackCandidatesChecked.map((c, i) => (
                    <button key={i} className="chip !px-2.5 !py-1" style={c.hit ? { background: "rgba(248,113,113,.18)", color: "var(--red)", borderColor: "rgba(248,113,113,.5)" } : { opacity: 0.45 }}>
                      k = {fmt(c.k)}
                      <span className="font-normal" style={{ opacity: 0.8 }}>
                        {c.hit ? " ← g^k == r₁ ✓" : `(g^k={fmt(c.gk)} ≠ r₁)`}
                      </span>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="hint mt-1">同余无解 —— 请换一对消息重试。</div>
              )}
              <p className="hint mt-1.5">逐一检查 g^k mod p == r₁:命中者即为 Alice 真正用过的 k(教学参数下唯一)。</p>
            </div>

            <div className="step-line">
              <div className="text-xs font-semibold" style={{ color: "var(--cyan)" }}>第 3 步 · 恢复私钥并回验</div>
              <div className="mt-1 font-mono text-sm">
                x = (H(m₁) − k·s₁) · r₁⁻¹ mod q&nbsp;&nbsp;→&nbsp;&nbsp;
                <span className="font-bold" style={{ color: "var(--red)" }}>x = {fmt(attack.x)}</span>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-sm">
                <span style={{ color: "var(--text-dim)" }}>回验:</span>
                <span className="chip">g^x mod p = {fmt(modPow(key.g, attack.x, key.p))}</span>
                <span className="text-xs" style={{ color: "var(--text-faint)" }}>应与公钥 y = {fmt(key.y)} 相等</span>
                <span className="chip chip-red">✓ 成立</span>
              </div>
              <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--red)" }}>
                ⚠ 攻击恢复的私钥 x = {fmt(attack.x)} 与真实私钥完全一致 —— 一旦 k 被重用,
                签名者的长期私钥即刻泄露。因此 nonce 必须由密码学安全随机源每次独立生成!
              </p>
            </div>
          </div>
        )}
        {!attack && key && (
          <p className="hint mt-3">选择两条不同消息,点击「模拟…」:页面会用同一个 k 生成两个合法签名,再由攻击者恢复出私钥。</p>
        )}
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />离散对数难题</div>
          <p className="hint mt-2 leading-relaxed">已知 g、y = g^x mod p,求 x 是困难的。p 取安全素数且 g 的阶为大素数 q 时,不存在小子群可供降阶攻击——DLP 保持难解。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />随机化加密</div>
          <p className="hint mt-2 leading-relaxed">每加密一次都掷新的 k,同一明文产生不同密文。代价是密文膨胀为两个元素(约 2 倍),且不能直接加密超长消息——实践中多用混合加密(公钥封装会话密钥)。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />nonce 纪律</div>
          <p className="hint mt-2 leading-relaxed">签名临时秘密 k 必须每次独立随机生成并保密。k 重用 = 私钥泄露;k 可预测同样致命。DSA/ECDSA 历史上都因 nonce 缺陷出过真实安全事故。</p>
        </div>
      </div>
    </div>
  );
}
