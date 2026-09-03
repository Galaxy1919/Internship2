"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { rc4Crypt, rc4Keystream, rc4Trace } from "@/lib/rc4";
import { strToBytes, bytesToHex, hexToBytes, bytesToStr } from "@/lib/bytes";

const C = "#38bdf8";

const EXAMPLES = [
  { key: "Key", plain: "Plaintext" },
  { key: "实习密钥", plain: "RC4 流密码演示：信息安全实训 2026" },
  { key: "0123456789abcdef", plain: "Stream cipher demo with RC4 in browser" },
];

export default function Rc4Page() {
  const [plain, setPlain] = useState("RC4 流密码演示：信息安全实训 2026");
  const [key, setKey] = useState("实习密钥");
  const [cipherHex, setCipherHex] = useState("");

  const keyBytes = useMemo(() => strToBytes(key), [key]);
  const plainBytes = useMemo(() => strToBytes(plain), [plain]);
  const n = plainBytes.length;

  // 加密 + 密钥流（加解密同一函数：异或自反）
  const cipher = useMemo(() => {
    try {
      return rc4Crypt(plainBytes, keyBytes);
    } catch {
      return null;
    }
  }, [plainBytes, keyBytes]);

  const keystream = useMemo(() => rc4Keystream(keyBytes, n), [keyBytes, n]);
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
      return bytesToStr(rc4Crypt(cipher, keyBytes)) === plain;
    } catch {
      return false;
    }
  }, [cipher, keyBytes, plain]);

  // KSA 后的 S 盒 + PRGA 前 8 步明细
  const trace = useMemo(() => {
    try {
      return rc4Trace(keyBytes, 8);
    } catch {
      return null;
    }
  }, [keyBytes]);

  // 解密实验：粘贴 hex 密文
  const decResult = useMemo(() => {
    try {
      if (!cipherHex.trim()) return { ok: true as const, text: "" };
      const c = hexToBytes(cipherHex);
      return { ok: true as const, text: bytesToStr(rc4Crypt(c, keyBytes)) };
    } catch (e) {
      return { ok: false as const, text: (e as Error).message };
    }
  }, [cipherHex, keyBytes]);

  // ---- RFC 6229 标准向量（固定输入，内部计算）----
  const VECTORS = [
    {
      name: "RFC 6229 · 密钥 0102…10",
      detail: "密钥流前 16 字节（offset 0）",
      expected: "9ac7cc9a609d1ef7b2932899cde41b97",
      mine: bytesToHex(rc4Keystream(hexToBytes("0102030405060708090a0b0c0d0e0f10"), 16)),
    },
    {
      name: "经典示例 · Key / Plaintext",
      detail: "明文 Plaintext（9 字节）的密文",
      expected: "bbf316e8d940af0ad3",
      mine: bytesToHex(rc4Crypt(strToBytes("Plaintext"), strToBytes("Key"))),
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: C }}>Lab 05 · 流密码</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">RC4 流密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          RC4（Rivest Cipher 4）由 Ron Rivest 于 1987 年设计，曾是 SSL/TLS、WEP 与 WPA-TKIP 的主流加密算法。
          它用<strong style={{ color: "var(--text)" }}>密钥调度（KSA）</strong>把密钥打散成一个 256 字节的 S 盒，
          再用<strong style={{ color: "var(--text)" }}>伪随机生成（PRGA）</strong>不断交换 S 盒元素并输出字节，形成与明文等长的密钥流，
          最后逐字节异或完成加解密。本页算法与仓库内 <span className="mono text-xs">stream/RC4/main.py</span> 完全一致。
        </p>
      </div>

      {/* 输入 */}
      <div className="panel p-5">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label">明文</label>
            <textarea
              className="input min-h-[96px] resize-y"
              value={plain}
              onChange={(e) => setPlain(e.target.value)}
              placeholder="输入要加密的文本…"
            />
          </div>
          <div>
            <label className="field-label">密钥（任意长度文本，按 UTF-8 取字节）</label>
            <input className="input" value={key} onChange={(e) => setKey(e.target.value)} placeholder="如 Key、实习密钥…" />
            <div className="mt-3 space-y-2">
              <div className="kv"><span className="k">密钥长度</span><span className="v">{keyBytes.length} B</span></div>
              <div className="kv"><span className="k">明文长度（= 密钥流长度）</span><span className="v">{n} B</span></div>
            </div>
          </div>
        </div>
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

      {/* S 盒与 PRGA 可视化 */}
      {trace && (
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />KSA 后的 S 盒与 PRGA 前 8 步</div>
          <p className="hint mt-1">KSA 把密钥扩散到整个 0~255 的 S 盒；PRGA 每步交换两个元素并吐出一个密钥流字节。下方为前 8 步明细。</p>
          <div className="mt-3 overflow-x-auto">
            <div
              className="mx-auto"
              style={{ display: "grid", gridTemplateColumns: "repeat(16, 27px)", gap: 2, width: "max-content" }}
            >
              {Array.from(trace.sbox).map((b, i) => (
                <div
                  key={i}
                  className="flex items-center justify-center rounded font-mono text-[10px]"
                  style={{
                    width: 27, height: 27,
                    border: "1px solid var(--border)",
                    background: "rgba(2,6,17,.45)",
                    color: i < keyBytes.length ? C : "var(--text-dim)",
                  }}
                  title={`S[${i}] = ${b} (0x${b.toString(16).padStart(2, "0")})`}
                >
                  {b.toString(16).padStart(2, "0")}
                </div>
              ))}
            </div>
            <p className="hint mt-2 text-center">密钥前 {Math.min(keyBytes.length, 256)} 字节在 S 盒中的最终位置以蓝色标出 —— 这就是 KSA 的“搅动”结果。</p>
          </div>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr style={{ color: "var(--text-faint)" }}>
                  <th className="pb-2 pr-3 font-medium">步</th>
                  <th className="pb-2 pr-3 font-medium">i</th>
                  <th className="pb-2 pr-3 font-medium">j = (j+S[i]) mod 256</th>
                  <th className="pb-2 pr-3 font-medium">交换 S[i] ↔ S[j]</th>
                  <th className="pb-2 font-medium">输出 S[(S[i]+S[j]) mod 256]</th>
                </tr>
              </thead>
              <tbody>
                {trace.steps.map((s, idx) => (
                  <tr key={idx} className="border-t" style={{ borderColor: "var(--border)" }}>
                    <td className="py-1.5 pr-3" style={{ color: "var(--text-faint)" }}>{idx + 1}</td>
                    <td className="py-1.5 pr-3">{String(s.i).padStart(3, " ")}</td>
                    <td className="py-1.5 pr-3">{String(s.j).padStart(3, " ")}</td>
                    <td className="py-1.5 pr-3" style={{ color: "var(--text-dim)" }}>
                      {s.i} ↔ {s.j}
                    </td>
                    <td className="py-1.5" style={{ color: C }}>0x{s.out.toString(16).padStart(2, "0")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 结果 */}
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
            <p className="hint mt-3">密文含不可打印字节（UTF-8 被异或打散），请用下方 hex 形式查看或直接粘贴到右侧解密。</p>
          )}
          <label className="field-label mt-4">密文（hex）</label>
          <div className="output min-h-[52px] break-all">{cipherHexOut || "—"}</div>
          <div className="mt-3 flex items-center gap-2">
            <button
              className="btn btn-ghost text-xs"
              onClick={() => setCipherHex(cipherHexOut)}
            >
              用此密文去解密
            </button>
            <span className={`chip ${roundtripOk ? "" : "chip-red"}`}>
              {roundtripOk ? "✓ 加解密往返一致（异或自反）" : "等待输入…"}
            </span>
          </div>
        </div>

        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />解密（密文 hex → 明文）</div>
          <p className="hint mt-1">RC4 解密就是再异或一次同一密钥流，因此函数与加密完全相同。</p>
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

      {/* RFC 6229 标准向量 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" />RFC 6229 标准向量验证</div>
        <p className="hint mt-1">RFC 6229 是 RC4 的官方测试向量集：实现正确则密钥流必须逐字节吻合。</p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {VECTORS.map((v) => {
            const ok = v.mine === v.expected;
            return (
              <div key={v.name} className="rounded-lg border p-3" style={{ borderColor: ok ? "rgba(74,222,128,.3)" : "var(--border)" }}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs" style={{ color: "var(--text-dim)" }}>{v.name}</span>
                  {ok ? <span className="chip">✓ 通过</span> : <span className="chip chip-red">✗ 不符</span>}
                </div>
                <div className="mt-2 text-[11px]" style={{ color: "var(--text-faint)" }}>{v.detail}</div>
                <div className="mt-1.5 flex items-center gap-2">
                  <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>实现</span>
                  <span className="break-all font-mono text-xs" style={{ color: ok ? "var(--accent)" : "var(--red)" }}>{v.mine}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>标准</span>
                  <span className="break-all font-mono text-xs" style={{ color: "var(--text-dim)" }}>{v.expected}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />两阶段结构</div>
          <p className="hint mt-2 leading-relaxed">KSA 负责把任意长度密钥“搅”进 S 盒形成初始状态；PRGA 之后每步只依赖内部状态与交换，密钥不再参与——这正是流密码“一次生成整段密钥流”的模型。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />异或自反</div>
          <p className="hint mt-2 leading-relaxed">因为 C = P ⊕ K 且 P = C ⊕ K，加密和解密是同一个函数。这个性质流密码通用（RC4、CA、AES-CTR 都是），实现简单且适合逐字节流式处理。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />现实弱点</div>
          <p className="hint mt-2 leading-relaxed">RC4 已被证明存在密钥相关性与 IV 重用弱点（WEP 因此被彻底攻破），RFC 7465 已禁止其在 TLS 中使用，现代由 AES-CTR / ChaCha20 取代。</p>
        </div>
      </div>
    </div>
  );
}
