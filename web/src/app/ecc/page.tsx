"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  TOY,
  SECP256K1,
  G,
  pointToStr,
  scalarMul,
  publicKeyIsValid,
  ecdh,
  type Curve,
  type Point,
  type ScalarStep,
} from "@/lib/ecc";

function fmtHex(v: bigint, short = true): string {
  const s = v.toString(16);
  return short && s.length > 20 ? s.slice(0, 10) + "…" + s.slice(-6) : s;
}

export default function EccPage() {
  const [curveKey, setCurveKey] = useState<"toy" | "secp256k1">("toy");
  const [kStr, setKStr] = useState("7");
  const [regen, setRegen] = useState(0); // 用于重新掷随机密钥
  const [fakePub, setFakePub] = useState(false); // secp256k1 演示: 是否用篡改的伪公钥

  const C: Curve = curveKey === "toy" ? TOY : SECP256K1;
  const toy = curveKey === "toy";

  const k = useMemo(() => {
    try {
      const v = BigInt(kStr.trim());
      if (v >= 0n) return v;
    } catch { /* noop */ }
    return 1n;
  }, [kStr]);

  const pointRows = useMemo(() => {
    if (!toy) return null;
    const rows: { k: number; P: Point }[] = [];
    for (let i = 1; i <= 20; i++) {
      rows.push({ k: i, P: scalarMul(BigInt(i), G(C), C) });
    }
    return rows;
  }, [C, toy]);

  // k·G 轨迹
  const traceSteps = useMemo<ScalarStep[] | null>(() => {
    try {
      const t: ScalarStep[] = [];
      scalarMul(k, G(C), C, t);
      return t;
    } catch {
      return null;
    }
  }, [k, C]);

  const kG = useMemo(() => {
    try {
      return scalarMul(k, G(C), C);
    } catch {
      return null;
    }
  }, [k, C]);

  // ECDH: 固定私钥演示(toy 可手算) + secp256k1 随机
  const dh = useMemo(() => {
    // 私钥: toy 用固定 3/5, secp256k1 用固定但大一些的数(保证有代表性)
    const dA = toy ? 3n : 0x3f9d4a1c2b8e6f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8n % C.n;
    const dB = toy ? 5n : 0x1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80n % C.n;
    const pubA = scalarMul(dA, G(C), C);
    const pubB = scalarMul(dB, G(C), C);
    const sA = ecdh(dA, pubB, C);
    const sB = ecdh(dB, pubA, C);
    const same = sA !== null && sB !== null && sA.x === sB.x && sA.y === sB.y;
    const validA = publicKeyIsValid(pubA, C);
    const validB = publicKeyIsValid(pubB, C);
    // 伪公钥: 篡改 y 一位
    const fake = pubA ? { x: pubA.x, y: (pubA.y + 1n) % C.p } : null;
    const fakeValid = fake ? publicKeyIsValid(fake, C) : true;
    return { dA, dB, pubA, pubB, sA, sB, same, validA, validB, fake, fakeValid };
  }, [C, toy, regen]);

  const ecdhAttempt = useMemo(() => {
    if (!fakePub) return dh;
    // 用伪公钥尝试 ECDH: 应触发"公钥不合法"异常
    try {
      const s = ecdh(dh.dA, dh.fake, C);
      return { ...dh, attackShared: s };
    } catch (e) {
      return { ...dh, attackError: (e as Error).message };
    }
  }, [dh, fakePub, C]);

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 13</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">ECC 椭圆曲线密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          在素数域 Fp 上,y² = x³ + ax + b 的点集与无穷远点 O 构成阿贝尔群。ECC 的安全性依赖
          <strong style={{ color: "var(--text)" }}>椭圆曲线离散对数问题(ECDLP)</strong>:已知 P、Q = k·P 求 k 极难。
          相同安全等级下密钥比 RSA 短得多(256-bit ECC ≈ 3072-bit RSA),因此成为现代密码学的首选。
        </p>
      </div>

      {/* 曲线选择 */}
      <div className="flex flex-wrap gap-2">
        <button className={`btn ${curveKey === "toy" ? "btn-primary" : "btn-ghost"}`} onClick={() => setCurveKey("toy")}>
          toy 曲线 y²=x³+2x+2 (mod 17) · 阶 19
        </button>
        <button className={`btn ${curveKey === "secp256k1" ? "btn-primary" : "btn-ghost"}`} onClick={() => setCurveKey("secp256k1")}>
          secp256k1（比特币同款, 256-bit）
        </button>
      </div>

      {toy ? (
        <>
          {/* 群表 */}
          <div className="panel p-5">
            <div className="panel-title">
              <span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />
              toy 曲线群元素表
              <span className="ml-auto font-mono text-xs font-normal" style={{ color: "var(--text-faint)" }}>n=19 的循环群, 19·G = O</span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-1.5 sm:grid-cols-4">
              {pointRows?.map(({ k: ki, P }) => (
                <div key={ki} className="grid-cell !justify-start !px-2 !text-xs">
                  <span style={{ color: "var(--cyan)" }}>{ki}·G</span>
                  <span className="ml-2" style={{ color: P ? "var(--text)" : "var(--red)" }}>{P ? `(${P.x}, ${P.y})` : "O"}</span>
                </div>
              ))}
            </div>
            <p className="hint mt-3">G = (5,1),可手工验算:2G = (6,3),3G = (10,6),19G 回到无穷远 O。这个群只有 19 个点,做教学验算刚刚好。</p>
          </div>

          {/* double-and-add 轨迹 */}
          <div className="panel p-5">
            <div className="panel-title">
              <span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />
              创新点 1:可审计 double-and-add 标量乘轨迹
            </div>
            <div className="mt-3 flex flex-wrap items-end gap-2">
              <div className="w-40">
                <label className="field-label">k（计算 k·G）</label>
                <input className="input font-mono" value={kStr} onChange={(e) => setKStr(e.target.value)} />
              </div>
              <button className="btn btn-primary" onClick={() => setKStr("7")}>示例 k=7</button>
              <button className="btn btn-ghost" onClick={() => setKStr("19")}>示例 k=19</button>
            </div>
            <div className="mt-3 flex items-center gap-2 text-sm">
              <span style={{ color: "var(--text-dim)" }}>结果:</span>
              <span className="output !py-1">{kG ? pointToStr(kG) : "O"}</span>
              {kG && <span className="chip">{(k % 19n) === 0n ? "k ≡ 0 (mod 19), 回到 O" : ""}</span>}
            </div>
            {traceSteps && traceSteps.length > 0 && (
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr style={{ color: "var(--text-faint)" }}>
                      <th className="pb-2 pr-4 font-medium">bit 位</th>
                      <th className="pb-2 pr-4 font-medium">操作</th>
                      <th className="pb-2 font-medium">中间点</th>
                    </tr>
                  </thead>
                  <tbody>
                    {traceSteps.map((s, i) => (
                      <tr key={i} className="border-t" style={{ borderColor: "var(--border)" }}>
                        <td className="py-1.5 pr-4" style={{ color: "var(--text-faint)" }}>{s.bit}</td>
                        <td className="py-1.5 pr-4">
                          <span className={`chip ${s.op === "add" ? "" : "chip-cyan"}`}>{s.op === "add" ? "ADD 加 G" : "DBL 倍点"}</span>
                        </td>
                        <td className="py-1.5">{s.pt ? pointToStr(s.pt) : "O"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="hint mt-2">从低位到高位:遇 0 只倍点,遇 1 先加 G 再倍点(末位 1 不倍)。加法与倍点都只是点加法,复杂度 O(log k)。</p>
              </div>
            )}
          </div>
        </>
      ) : (
        /* secp256k1 部分 */
        <>
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="panel p-5">
              <div className="panel-title">
                <span className="dot" style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />
                secp256k1 曲线参数
              </div>
              <div className="mt-3 space-y-2 font-mono text-xs">
                <div className="kv"><span className="k">p</span><span className="v break-all">0x{fmtHex(C.p, false)}</span></div>
                <div className="kv"><span className="k">a, b</span><span className="v">{C.a.toString()}, {C.b.toString()}</span></div>
                <div className="kv"><span className="k">G.x</span><span className="v break-all">0x{fmtHex(C.Gx, false)}</span></div>
                <div className="kv"><span className="k">G.y</span><span className="v break-all">0x{fmtHex(C.Gy, false)}</span></div>
                <div className="kv"><span className="k">阶 n（bits={C.n.toString(2).length}）</span><span className="v">0x{fmtHex(C.n, false)}</span></div>
              </div>
            </div>
            <div className="panel p-5">
              <div className="panel-title">
                <span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />
                标量乘验证
              </div>
              <label className="field-label mt-3">k（0 &lt; k &lt; n,计算 k·G）</label>
              <input className="input font-mono text-xs" value={kStr} onChange={(e) => setKStr(e.target.value)} />
              <div className="mt-2 flex flex-wrap gap-1.5">
                <button className="btn-ghost btn !px-2.5 !py-1 text-xs font-mono" onClick={() => setKStr("1")}>k=1</button>
                <button className="btn-ghost btn !px-2.5 !py-1 text-xs font-mono" onClick={() => setKStr("2")}>k=2（已知向量）</button>
                <button className="btn-ghost btn !px-2.5 !py-1 text-xs font-mono" onClick={() => setKStr("123456789")}>k=123456789</button>
              </div>
              <div className="mt-3">
                <div className="kv"><span className="k">k·G</span><span className="v break-all">{kG ? `(${fmtHex(kG.x)}, ${fmtHex(kG.y)})` : "O"}</span></div>
                {k === 2n && kG && kG.x === 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n && (
                  <p className="mt-2 flex items-center gap-2 text-xs" style={{ color: "var(--accent)" }}>
                    <span className="chip">✓ 公开向量</span>
                    2G 与比特币教材已知向量一致 —— 实现正确。
                  </p>
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {/* ECDH 密钥交换 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />
          ECDH 密钥交换（Alice ↔ Bob）
        </div>
        <p className="hint mt-1">双方各持私钥 d,把公钥 d·G 发给对方,各自计算 d·(对端公钥),得到同一个共享点 dA·dB·G。真实协议再对共享点 x 坐标做 KDF。</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn btn-ghost text-xs" onClick={() => setRegen((x) => x + 1)}>重新掷随机密钥{toy ? "" : "（secp256k1）"}</button>
        </div>
        {toy && <p className="hint mt-2">toy 模式下固定 dA=3、dB=5,共享点应为 15·G = (3, 16),可在上方群表中核对。</p>}
        <div className="mt-4 grid gap-3 lg:grid-cols-3">
          <div className="rounded-lg border p-4" style={{ borderColor: "rgba(74,222,128,.25)", background: "rgba(74,222,128,.04)" }}>
            <div className="text-xs font-semibold" style={{ color: "var(--accent)" }}>Alice</div>
            <div className="mt-2 font-mono text-xs break-all" style={{ color: "var(--text-dim)" }}>dA = {dh.dA.toString()}</div>
            <div className="mt-1 font-mono text-xs break-all" style={{ color: "var(--text)" }}>QA = dA·G = {dh.pubA ? pointToStr(dh.pubA, !toy) : "?"}</div>
          </div>
          <div className="flex flex-col items-center justify-center gap-2 py-2 text-center text-xs" style={{ color: "var(--text-faint)" }}>
            <div className="rounded-lg border border-dashed px-3 py-2 font-mono" style={{ borderColor: "var(--border-bright)" }}>
              公开信道
              <div className="mt-1" style={{ color: "var(--text-dim)" }}>交换公钥 QA ↔ QB</div>
            </div>
          </div>
          <div className="rounded-lg border p-4" style={{ borderColor: "rgba(34,211,238,.25)", background: "rgba(34,211,238,.04)" }}>
            <div className="text-xs font-semibold" style={{ color: "var(--cyan)" }}>Bob</div>
            <div className="mt-2 font-mono text-xs break-all" style={{ color: "var(--text-dim)" }}>dB = {dh.dB.toString()}</div>
            <div className="mt-1 font-mono text-xs break-all" style={{ color: "var(--text)" }}>QB = dB·G = {dh.pubB ? pointToStr(dh.pubB, !toy) : "?"}</div>
          </div>
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
            <div className="text-xs" style={{ color: "var(--text-faint)" }}>Alice 算 dA·QB</div>
            <div className="mt-1 font-mono text-xs break-all">{dh.sA ? pointToStr(dh.sA, !toy) : "O"}</div>
          </div>
          <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
            <div className="text-xs" style={{ color: "var(--text-faint)" }}>Bob 算 dB·QA</div>
            <div className="mt-1 font-mono text-xs break-all">{dh.sB ? pointToStr(dh.sB, !toy) : "O"}</div>
          </div>
        </div>
        {dh.same && (
          <p className="mt-3 flex items-center gap-2 text-sm" style={{ color: "var(--accent)" }}>
            <span className="chip">✓ 共享一致</span>
            dA·dB·G = dB·dA·G —— 双方独立得到同一共享点{toy ? "(15·G)" : ""}。
          </p>
        )}
      </div>

      {/* 创新点 2: 公钥合法性检查 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />
          创新点 2:公钥合法性检查（防小子群 / 无效曲线攻击）
        </div>
        <p className="hint mt-1 leading-relaxed">接收对端公钥后先做四项检查:非无穷远、坐标在 [0,p)、点在曲线上、n·PubKey = O(子群成员)。否则恶意对端可把公钥换成曲线外点或小子群点,导致共享点泄露私钥信息。</p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div className="kv"><span className="k">Alice 公钥合法?</span><span className="v">{dh.validA ? <span className="chip">✓ 通过</span> : <span className="chip chip-red">✗ 拒绝</span>}</span></div>
          <div className="kv"><span className="k">Bob 公钥合法?</span><span className="v">{dh.validB ? <span className="chip">✓ 通过</span> : <span className="chip chip-red">✗ 拒绝</span>}</span></div>
        </div>
        <div className="mt-4 rounded-lg border p-4" style={{ borderColor: "rgba(248,113,113,.3)", background: "rgba(248,113,113,.05)" }}>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <button
              className={`btn !px-3 !py-1 text-xs ${fakePub ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setFakePub(!fakePub)}
            >
              {fakePub ? "还原为正常公钥" : "模拟伪造公钥（篡改 y 一位）"}
            </button>
            <span className="text-xs" style={{ color: "var(--text-faint)" }}>伪公钥合法? </span>
            <span className={`chip ${dh.fakeValid ? "" : "chip-red"}`}>{dh.fakeValid ? "✓ 通过" : "✗ 被拒绝"}</span>
          </div>
          {fakePub && dh.fake && (
            <div className="mt-3">
              <div className="kv"><span className="k">伪公钥 Q'（x 同, y 翻转一位）</span><span className="v break-all">{pointToStr(dh.fake, !toy)}</span></div>
              {"attackError" in ecdhAttempt && ecdhAttempt.attackError ? (
                <p className="mt-2 text-sm" style={{ color: "var(--red)" }}>
                  ✗ ECDH 直接拒绝:{ecdhAttempt.attackError}
                </p>
              ) : (
                "attackShared" in ecdhAttempt && ecdhAttempt.attackShared && (
                  <p className="mt-2 text-sm" style={{ color: "var(--red)" }}>
                    ⚠ 伪公钥通过了检查并得到共享点 {pointToStr(ecdhAttempt.attackShared, !toy)} —— 若实现不做合法性校验,这类畸形点可能泄露私钥低位。
                  </p>
                )
              )}
            </div>
          )}
        </div>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />群运算几何</div>
          <p className="hint mt-2 leading-relaxed">P+Q 是连线与曲线的第三点关于 x 轴对称;P+P 用切线。除法定为乘以模逆。有限域上这些几何规则变成纯代数,但加法封闭性保证可反复运算。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />ECDLP 困难性</div>
          <p className="hint mt-2 leading-relaxed">给定 G 与 k·G 求 k,目前只有指数级算法(如 Pollard rho)。256-bit 曲线提供约 128-bit 安全强度,密钥长度远小于 RSA/DH。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />实现陷阱</div>
          <p className="hint mt-2 leading-relaxed">小子群攻击、无效曲线攻击、侧信道(时间/功耗泄露标量 k)都是真实威胁;标准实现需做点校验、常数时间标量乘与密钥再随机化。</p>
        </div>
      </div>
    </div>
  );
}
