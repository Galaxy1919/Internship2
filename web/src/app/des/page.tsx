"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { desBlockCrypt, desEncrypt, desDecrypt, pkcs7Pad8 } from "@/lib/des";
import { strToBytes, bytesToHex, hexToBytes, bytesToStr, keyBytesFromText, bitDiff } from "@/lib/bytes";

const C = "#fb923c";

const EXAMPLES = [
  { key: "133457799BBCDFF1", plain: "Hello DES World" },
  { key: "secret", plain: "DES 数据加密标准演示：信息安全实训 2026" },
  { key: "0123456789ABCDEF", plain: "分组密码 · Feistel 结构" },
];

export default function DesPage() {
  const [plain, setPlain] = useState("DES 数据加密标准演示：信息安全实训 2026");
  const [key, setKey] = useState("secret");
  const [cipherHex, setCipherHex] = useState("");
  const [variant, setVariant] = useState(false);

  // 密钥：16 位 hex 按字节解析；否则 UTF-8 截断/补零到 8 字节
  const key8 = useMemo(() => {
    try {
      return keyBytesFromText(key, 8);
    } catch {
      return null;
    }
  }, [key]);

  const keyError = useMemo(() => {
    if (!key8) return "密钥格式错误";
    return null;
  }, [key8]);

  const plainBytes = useMemo(() => strToBytes(plain), [plain]);

  const cipher = useMemo(() => {
    if (!key8) return null;
    try {
      return desEncrypt(plainBytes, key8);
    } catch {
      return null;
    }
  }, [plainBytes, key8]);

  const cipherHexOut = useMemo(() => (cipher ? bytesToHex(cipher) : ""), [cipher]);
  const blockCount = useMemo(() => (cipher ? cipher.length / 8 : 0), [cipher]);

  // 首分组 16 轮轨迹（ECB 逐块独立，第一块最有代表性）
  const trace = useMemo(() => {
    if (!key8) return null;
    try {
      const padded = pkcs7Pad8(plainBytes);
      return desBlockCrypt(padded.slice(0, 8), key8).log;
    } catch {
      return null;
    }
  }, [plainBytes, key8]);

  const roundtripOk = useMemo(() => {
    if (!cipher || !key8) return false;
    try {
      return bytesToStr(desDecrypt(cipher, key8)) === plain;
    } catch {
      return false;
    }
  }, [cipher, key8, plain]);

  // 变异 S1 对照：第一个 S-box 所有输出循环 +1
  const variantResult = useMemo(() => {
    if (!key8 || plainBytes.length === 0) return null;
    try {
      const normal = desEncrypt(plainBytes, key8, false);
      const changed = desEncrypt(plainBytes, key8, true);
      return { normal: bytesToHex(normal), changed: bytesToHex(changed), diff: bitDiff(normal, changed) };
    } catch {
      return null;
    }
  }, [key8, plainBytes]);

  // 解密
  const decResult = useMemo(() => {
    if (!key8) return { ok: false as const, text: "密钥无效" };
    try {
      if (!cipherHex.trim()) return { ok: true as const, text: "" };
      const c = hexToBytes(cipherHex);
      return { ok: true as const, text: bytesToStr(desDecrypt(c, key8)) };
    } catch (e) {
      return { ok: false as const, text: (e as Error).message };
    }
  }, [cipherHex, key8]);

  // 标准向量：教材经典例（FIPS 81 / Stallings）
  const vector = useMemo(() => {
    const k = hexToBytes("133457799BBCDFF1");
    const p = hexToBytes("0123456789ABCDEF");
    const mine = bytesToHex(desBlockCrypt(p, k).ct);
    return { mine, expected: "85e813540f0ab405" };
  }, []);

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: C }}>Lab 07 · 分组密码</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">DES 数据加密标准</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          DES（FIPS 46-3）诞生于 1977 年，是第一个被广泛采用的现代对称分组密码：<strong style={{ color: "var(--text)" }}>64-bit 分组 + 56-bit 密钥 + 16 轮 Feistel 网络</strong>。
          每轮用子密钥对右半做 E 扩展 → 与子密钥异或 → 过 8 个 S-box → P 置换，再与左半异或后交换。
          加解密共用同一套硬件（解密仅将子密钥逆序使用）。本页算法为浏览器端从零实现，与 <span className="mono text-xs">Block/DES/main.py</span> 同构。
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
                  {ex.key.length > 10 ? `${ex.key.slice(0, 8)}…` : ex.key} / {ex.plain.slice(0, 10)}…
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="field-label">密钥（16 位 hex 或任意文本 → 8 字节）</label>
            <input className="input font-mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="133457799BBCDFF1 或 secret…" />
            {keyError && <p className="mt-2 text-xs" style={{ color: "var(--red)" }}>⚠ {keyError}</p>}
            {key8 && (
              <div className="mt-3 space-y-2">
                <div className="kv"><span className="k">实际使用密钥（8 字节 hex）</span><span className="v">{bytesToHex(key8)}</span></div>
                <div className="kv"><span className="k">明文 → PKCS#7 → 分组数</span><span className="v">{plainBytes.length} B → {blockCount} × 8B</span></div>
              </div>
            )}
            <p className="hint mt-2">DES 每字节密钥最低位为奇偶校验位，算法实际只用 56 bit，本实现不校验（与教材例一致）。</p>
          </div>
        </div>
      </div>

      {/* 轮函数可视化 */}
      {trace && (
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />16 轮 Feistel 轨迹（首分组）</div>
          <p className="hint mt-1">
            一轮：<span className="mono text-xs" style={{ color: "var(--accent)" }}>{"L_i = R_{i-1}，R_i = L_{i-1} ⊕ f(R_{i-1}, K_i)"}</span>，最后一轮不交换左右。
          </p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left font-mono text-[11px]">
              <thead>
                <tr style={{ color: "var(--text-faint)" }}>
                  <th className="pb-2 pr-3 font-medium">轮</th>
                  <th className="pb-2 pr-3 font-medium">子密钥 K_i（48 bit）</th>
                  <th className="pb-2 pr-3 font-medium">{"f(R_{i-1}, K_i)"}</th>
                  <th className="pb-2 pr-3 font-medium">L_i</th>
                  <th className="pb-2 font-medium">R_i</th>
                </tr>
              </thead>
              <tbody>
                {trace.map((t) => (
                  <tr key={t.round} className="border-t" style={{ borderColor: "var(--border)" }}>
                    <td className="py-1 pr-3" style={{ color: "var(--text-faint)" }}>{String(t.round).padStart(2, "0")}</td>
                    <td className="py-1 pr-3" style={{ color: "var(--text-dim)" }}>{t.subkey}</td>
                    <td className="py-1 pr-3" style={{ color: C }}>{t.f}</td>
                    <td className="py-1 pr-3">{t.lOut}</td>
                    <td className="py-1">{t.rOut}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="hint mt-3">S-box 是 DES 唯一的非线性部件：48 bit 经 8 个 6→4 的 S-box 压缩回 32 bit。轨迹中 <span style={{ color: C }}>f 列</span> 是每轮的核心扩散值。</p>
        </div>
      )}

      {/* 结果 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />加密结果</div>
          <label className="field-label mt-3">密文（hex）</label>
          <div className="output min-h-[52px] break-all">{cipherHexOut || "—"}</div>
          <p className="hint mt-2">分组密码输出恒为 8 的倍数（PKCS#7 填充）；若明文刚好整除则补一整块 0x08。密文通常不可打印，用 hex 查看。</p>
          <div className="mt-3 flex items-center gap-2">
            <button className="btn btn-ghost text-xs" onClick={() => setCipherHex(cipherHexOut)}>用此密文去解密</button>
            <span className={`chip ${roundtripOk ? "" : "chip-red"}`}>{roundtripOk ? "✓ 解密还原一致" : "等待输入…"}</span>
          </div>

          {/* 变异 S1 对照 */}
          {variantResult && (
            <div className="mt-5 rounded-lg border p-4" style={{ borderColor: "rgba(251,191,36,.25)", background: "rgba(2,6,17,.4)" }}>
              <div className="flex items-center justify-between">
                <div className="panel-title !mb-0"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />变异 S1 对照实验</div>
                <button
                  className={`btn !px-2.5 !py-1 text-xs ${variant ? "btn-primary" : "btn-ghost"}`}
                  onClick={() => setVariant(!variant)}
                >
                  {variant ? "✓ 变异已启用（S1 循环 +1）" : "启用变异 S1"}
                </button>
              </div>
              <p className="hint mt-2">把第一个 S-box 的所有输出循环 +1（模拟组件被篡改），观察密文的雪崩程度——这正是分组密码“组件任何微小变化都不可接受”的体现。</p>
              <div className="mt-3 space-y-2">
                <div className="kv"><span className="k">标准密文</span><span className="v break-all">{variantResult.normal.slice(0, 64)}{variantResult.normal.length > 64 ? "…" : ""}</span></div>
                <div className="kv"><span className="k">变异密文</span><span className="v break-all" style={{ color: "var(--amber)" }}>{variantResult.changed.slice(0, 64)}{variantResult.changed.length > 64 ? "…" : ""}</span></div>
              </div>
              <div className="mt-2 kv"><span className="k">差异比特</span><span className="v" style={{ color: "var(--amber)" }}>{variantResult.diff} bit（理想约一半）</span></div>
            </div>
          )}
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

      {/* 标准向量 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" />标准向量验证</div>
        <p className="hint mt-1">教材经典向量（FIPS 81 示例）：密钥与明文均按 hex 输入，与本页上方文本输入互不影响。</p>
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <div className="rounded-lg border p-3" style={{ borderColor: vector.mine === vector.expected ? "rgba(74,222,128,.3)" : "var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs" style={{ color: "var(--text-dim)" }}>key=133457799BBCDFF1 · pt=0123456789ABCDEF</span>
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
            <div className="text-xs" style={{ color: "var(--text-dim)" }}>ECB 模式说明</div>
            <p className="hint mt-2 leading-relaxed">当前实现为 ECB：每个 8 字节分组独立加密，相同的明文分组产生相同密文。教学演示直观，真实系统建议 CBC / GCM 并配合随机 IV。</p>
          </div>
        </div>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />Feistel 网络</div>
          <p className="hint mt-2 leading-relaxed">每轮只对右半做非线性变换再与左半异或，左右交换。解密只需把子密钥逆序使用，加解密电路完全复用——这是 1970 年代硬件时代的巧妙设计。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />子密钥与 S-box</div>
          <p className="hint mt-2 leading-relaxed">56-bit 密钥经 PC-1 拆成两半、循环左移后由 PC-2 抽出 48 bit 子密钥；轮函数里 E 扩展负责扩散，8 个 S-box 是唯一非线性部件（抗差分/线性攻击的关键）。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />安全现状</div>
          <p className="hint mt-2 leading-relaxed">56-bit 密钥空间太小：1999 年 EFF 的 Deep Crack 22 小时穷举攻破。DES 已被 3DES 过渡、最终被 AES 取代，如今仅具教学与历史意义。</p>
        </div>
      </div>
    </div>
  );
}
