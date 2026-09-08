"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  SM2_CURVE,
  sm3,
  sm2Sign,
  sm2Verify,
  sm2Encrypt,
  sm2Decrypt,
  computeZA,
  generateKeypair,
  bytesToHex,
} from "@/lib/sm2";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

function hexOf(b: Uint8Array): string {
  return bytesToHex(b);
}

export default function Sm2Page() {
  const [userId, setUserId] = useState("1234567812345678");
  const [msg, setMsg] = useState("hello SM2 数字签名 2026");
  const [sig, setSig] = useState<{ r: bigint; s: bigint; e: bigint; za: Uint8Array } | null>(null);
  const [keypair, setKeypair] = useState(() => generateKeypair());
  const [tamper, setTamper] = useState(false);
  const [wrongId, setWrongId] = useState(false);

  // PKE 状态
  const [pkeMsg, setPkeMsg] = useState("SM2-PKE 演示 明文 message");
  const [pkeCt, setPkeCt] = useState<Uint8Array | null>(null);
  const [pkeK, setPkeK] = useState<bigint | null>(null);

  const userIdBytes = useMemo(() => enc(userId), [userId]);
  const za = useMemo(() => {
    try {
      return computeZA(userIdBytes, keypair.pub);
    } catch {
      return null;
    }
  }, [userIdBytes, keypair]);

  const doSign = () => {
    try {
      setSig(sm2Sign(enc(msg), keypair.d, keypair.pub, userIdBytes));
      setTamper(false);
      setWrongId(false);
    } catch {
      setSig(null);
    }
  };

  const doEncrypt = () => {
    try {
      const res = sm2Encrypt(enc(pkeMsg), keypair.pub);
      setPkeCt(res.ct);
      setPkeK(res.kUsed);
    } catch {
      setPkeCt(null);
    }
  };

  const verifyResult = useMemo(() => {
    if (!sig) return null;
    const targetMsg = tamper ? enc(msg + "!") : enc(msg);
    const targetId = wrongId ? enc("8765432187654321") : userIdBytes;
    return sm2Verify(targetMsg, sig.r, sig.s, keypair.pub, targetId);
  }, [sig, msg, tamper, wrongId, userIdBytes, keypair]);

  const pkeDecrypt = useMemo(() => {
    if (!pkeCt) return null;
    try {
      return sm2Decrypt(pkeCt, keypair.d);
    } catch {
      return null;
    }
  }, [pkeCt, keypair]);

  // 展示用: 拼接各部分布局
  const pkeLayout = useMemo(() => {
    if (!pkeCt) return null;
    return {
      c1: pkeCt.slice(0, 65),
      c3: pkeCt.slice(65, 97),
      c2: pkeCt.slice(97),
    };
  }, [pkeCt]);

  const fmtBig = (v: bigint, n = 12) => {
    const s = v.toString(16);
    return s.length > n ? "0x" + s.slice(0, n) + "…" : "0x" + s;
  };

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 14</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">SM2 国密公钥密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          中国国家密码管理局发布的椭圆曲线公钥算法(GM/T 0003-2012),基于 256-bit 素数域固定曲线。
          与 ECDSA 的关键区别:<strong style={{ color: "var(--text)" }}>摘要用国密 SM3</strong>(本页从零实现,对齐 GM/T 0004 官方向量),
          签名前计算 <strong style={{ color: "var(--text)" }}>ZA 预处理值</strong>把用户 ID 与公钥绑进消息哈希,加密采用 C1||C3||C2 布局并带完整性校验。
        </p>
      </div>

      {/* SM3 自检 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />
            创新点 1:SM3 摘要（从零实现）
          </div>
          <p className="hint mt-1">SM3 输出 32 字节,压缩函数 64 轮,与 SHA-256 结构类似但常量与置换不同。下方两条为 GM/T 0004-2012 官方测试向量。</p>
          <div className="mt-3 space-y-2">
            <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
              <div className="text-xs" style={{ color: "var(--text-faint)" }}>SM3("abc")</div>
              <div className="mt-1 font-mono text-xs break-all" style={{ color: "var(--accent)" }}>
                {hexOf(sm3(enc("abc")))}
              </div>
              <div className="mt-1 flex items-center gap-2 text-xs">
                <span className="chip">✓ 官方</span>
                <span className="font-mono break-all" style={{ color: "var(--text-faint)" }}>66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0</span>
              </div>
            </div>
            <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
              <div className="text-xs" style={{ color: "var(--text-faint)" }}>SM3("abcd"×16 · 512-bit)</div>
              <div className="mt-1 font-mono text-xs break-all" style={{ color: "var(--accent)" }}>
                {hexOf(sm3(enc("abcd".repeat(16))))}
              </div>
              <div className="mt-1 flex items-center gap-2 text-xs">
                <span className="chip">✓ 官方</span>
                <span className="font-mono break-all" style={{ color: "var(--text-faint)" }}>debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732</span>
              </div>
            </div>
          </div>
        </div>

        {/* 密钥与 ZA */}
        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />
            密钥对与 ZA 预处理（创新点 2）
          </div>
          <p className="hint mt-1">ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA),把用户身份与公钥注入签名 —— 防止跨用户重放签名。</p>
          <div className="mt-3 grid gap-2">
            <div className="kv"><span className="k">私钥 d</span><span className="v break-all">{fmtBig(keypair.d, 20)}</span></div>
            <div className="kv"><span className="k">公钥 Q.x</span><span className="v break-all">{keypair.pub ? fmtBig(keypair.pub.x, 20) : "—"}</span></div>
            <div className="kv"><span className="k">公钥 Q.y</span><span className="v break-all">{keypair.pub ? fmtBig(keypair.pub.y, 20) : "—"}</span></div>
            <div className="kv" style={{ borderColor: "rgba(34,211,238,.3)" }}><span className="k">ZA（32B）</span><span className="v break-all">{za ? hexOf(za) : "—"}</span></div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="btn btn-ghost text-xs" onClick={() => setKeypair(generateKeypair())}>重新生成密钥对</button>
          </div>
          <div className="mt-3">
            <label className="field-label">用户标识 ID_A（参与 ZA 计算）</label>
            <input className="input font-mono" value={userId} onChange={(e) => setUserId(e.target.value)} />
          </div>
          <p className="hint mt-2">默认 16 字节 "1234567812345678" 是 GM/T 0003.5 规定值;若收发双方 ID 不同,签名将无法验证。</p>
        </div>
      </div>

      {/* 签名 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />
          SM2 数字签名（DSA）
        </div>
        <p className="hint mt-1 leading-relaxed">
          签名:先算 e = SM3(ZA || M),随机 k 求 (x1,y1) = k·G,得 r = (e + x1) mod n;s = (1+d)⁻¹·(k − r·d) mod n。
          验证:由 (r+s)·pub + s·G 恢复 x1′,比较 (e + x1′) mod n == r。
        </p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[240px] flex-1">
            <label className="field-label">待签名消息</label>
            <input className="input" value={msg} onChange={(e) => setMsg(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={doSign}>签名</button>
        </div>
        {sig && (
          <div className="mt-4 grid gap-2 md:grid-cols-3">
            <div className="kv"><span className="k">e = SM3(ZA‖M)</span><span className="v break-all">{fmtBig(sig.e, 16)}</span></div>
            <div className="kv"><span className="k">r</span><span className="v break-all">{fmtBig(sig.r, 16)}</span></div>
            <div className="kv"><span className="k">s</span><span className="v break-all">{fmtBig(sig.s, 16)}</span></div>
          </div>
        )}
        {sig && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button className={`btn !px-3 !py-1 text-xs ${!tamper && !wrongId ? "btn-primary" : "btn-ghost"}`} onClick={() => { setTamper(false); setWrongId(false); }}>
              验证原消息（原 ID）
            </button>
            <button className={`btn !px-3 !py-1 text-xs ${tamper ? "btn-primary" : "btn-ghost"}`} onClick={() => { setTamper(true); setWrongId(false); }}>
              验证被篡改消息
            </button>
            <button className={`btn !px-3 !py-1 text-xs ${wrongId ? "btn-primary" : "btn-ghost"}`} onClick={() => { setWrongId(true); setTamper(false); }}>
              验证换用另一 ID
            </button>
            {verifyResult !== null && (
              <span className={`chip ${verifyResult ? "" : "chip-red"}`}>{verifyResult ? "✓ 签名有效" : "✗ 验证失败"}</span>
            )}
          </div>
        )}
        {sig && wrongId && verifyResult === false && (
          <p className="hint mt-2" style={{ color: "var(--red)" }}>ID 改变导致 ZA 不同,e 值不同,验证失败 —— 这就是 ZA 把签名"绑到用户身份"的效果。</p>
        )}
        {!sig && <p className="hint mt-3">点击「签名」后可用三个验证按钮切换消息/ID 观察结果翻转。</p>}
      </div>

      {/* 加密 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />
          SM2 公钥加密（PKE · C1‖C3‖C2）
        </div>
        <p className="hint mt-1 leading-relaxed">
          加密:随机 k,C1 = k·G;共享点 (x2,y2) = k·pub;t = KDF(x2‖y2),C2 = M ⊕ t;C3 = SM3(x2‖M‖y2)。
          输出 04‖x1‖y1‖C3‖C2 —— 密文自带完整性校验。
        </p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[240px] flex-1">
            <label className="field-label">明文（UTF-8,任意长度）</label>
            <input className="input" value={pkeMsg} onChange={(e) => setPkeMsg(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={doEncrypt}>加密</button>
        </div>
        {pkeCt && pkeLayout && (
          <div className="mt-4 space-y-2">
            <div className="kv"><span className="k">会话 k（随机,未公开）</span><span className="v break-all">{fmtBig(pkeK ?? 0n, 16)}</span></div>
            <div className="kv"><span className="k">C1 = k·G（04‖x1‖y1, 65B）</span><span className="v break-all">{hexOf(pkeLayout.c1)}</span></div>
            <div className="kv"><span className="k">C3 = SM3(x2‖M‖y2)（32B）</span><span className="v break-all">{hexOf(pkeLayout.c3)}</span></div>
            <div className="kv"><span className="k">C2 = M⊕KDF（{pkeLayout.c2.length}B）</span><span className="v break-all">{hexOf(pkeLayout.c2)}</span></div>
            <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
              <div className="text-xs" style={{ color: "var(--text-faint)" }}>完整密文（{pkeCt.length}B）</div>
              <div className="output mt-1.5 break-all !text-xs">{hexOf(pkeCt)}</div>
            </div>
            {pkeDecrypt ? (
              <p className="mt-2 flex items-center gap-2 text-sm" style={{ color: "var(--accent)" }}>
                <span className="chip">✓ 解密还原</span>
                {dec(pkeDecrypt)}
              </p>
            ) : (
              <p className="mt-2 text-sm" style={{ color: "var(--red)" }}>⚠ 解密失败（完整性校验未通过）。</p>
            )}
          </div>
        )}
        {!pkeCt && <p className="hint mt-3">输入明文后加密,观察密文布局与解密还原;再点一次加密会得到不同密文（随机 k）。</p>}
      </div>

      {/* 曲线参数 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />
          国密推荐曲线参数（GM/T 0003.5-2012,固定）
        </div>
        <div className="mt-3 grid gap-2 font-mono text-xs md:grid-cols-2">
          <div className="kv"><span className="k">p（256-bit）</span><span className="v break-all">0x{SM2_CURVE.p.toString(16)}</span></div>
          <div className="kv"><span className="k">n（阶,256-bit）</span><span className="v break-all">0x{SM2_CURVE.n.toString(16)}</span></div>
          <div className="kv"><span className="k">a</span><span className="v break-all">0x{SM2_CURVE.a.toString(16)}</span></div>
          <div className="kv"><span className="k">b</span><span className="v break-all">0x{SM2_CURVE.b.toString(16)}</span></div>
          <div className="kv"><span className="k">G.x</span><span className="v break-all">0x{SM2_CURVE.Gx.toString(16)}</span></div>
          <div className="kv"><span className="k">G.y</span><span className="v break-all">0x{SM2_CURVE.Gy.toString(16)}</span></div>
        </div>
        <p className="hint mt-3">曲线方程为 y² = x³ + ax + b (mod p)。与 secp256k1 / NIST P-256 参数都不同 —— 这是我国自研的标准曲线,由国家密码管理局发布。</p>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />国产密码体系</div>
          <p className="hint mt-2 leading-relaxed">SM2(公钥)、SM3(哈希)、SM4(对称)构成我国商用密码核心。SM2 与国际 ECDSA/ECIES 同级安全(约 128-bit),但算法细节、参数、编码全部自主可控。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />身份绑定 ZA</div>
          <p className="hint mt-2 leading-relaxed">把用户 ID 与公钥哈希进摘要,使签名无法在另一个身份/公钥下重放。这是 SM2 相比教科书 ECDSA 的重要工程改进。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />规范差异</div>
          <p className="hint mt-2 leading-relaxed">SM2 密文/签名常用 ASN.1 DER 编码传输;密钥交换(SM2-KE)本实现未含。生产使用仍需参考 GM/T 0003 各分册与密码模块检测要求。</p>
        </div>
      </div>
    </div>
  );
}
