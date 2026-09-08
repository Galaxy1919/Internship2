"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { md5Hex } from "@/lib/md5";
import { strToBytes, bytesToHex, bitDiff, bitRatio } from "@/lib/bytes";

const PRESETS = [
  { label: "空串", a: "", b: " " },
  { label: "abc", a: "abc", b: "abd" },
  { label: "fox 经典句", a: "The quick brown fox jumps over the lazy dog", b: "The quick brown fox jumps over the lazy cog" },
  { label: "中文", a: "密码学实验", b: "密码学实验！" },
];

function ByteRow({ label, bytes, diffMask }: { label: string; bytes: Uint8Array; diffMask: Uint8Array }) {
  return (
    <div className="flex items-start gap-2">
      <span className="mt-1.5 w-14 shrink-0 font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>{label}</span>
      <div className="flex flex-wrap gap-1">
        {Array.from(bytes).map((b, i) => (
          <span key={i} className={`byte-diff ${diffMask[i] ? "diff" : "same"}`}>
            {b.toString(16).padStart(2, "0")}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Md5Page() {
  const [text, setText] = useState("The quick brown fox jumps over the lazy dog");
  const [aText, setAText] = useState("The quick brown fox jumps over the lazy dog");
  const [bText, setBText] = useState("The quick brown fox jumps over the lazy cog");

  const digest = useMemo(() => md5Hex(strToBytes(text)), [text]);

  const aBytes = useMemo(() => strToBytes(aText), [aText]);
  const bBytes = useMemo(() => strToBytes(bText), [bText]);
  const aHex = useMemo(() => md5Hex(aBytes), [aBytes]);
  const bHex = useMemo(() => md5Hex(bBytes), [bBytes]);

  const aDigest = useMemo(() => {
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) out[i] = parseInt(aHex.substr(i * 2, 2), 16);
    return out;
  }, [aHex]);
  const bDigest = useMemo(() => {
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) out[i] = parseInt(bHex.substr(i * 2, 2), 16);
    return out;
  }, [bHex]);

  const diff = useMemo(() => {
    const n = Math.min(aDigest.length, bDigest.length);
    const mask = new Uint8Array(n);
    for (let i = 0; i < n; i++) mask[i] = aDigest[i] !== bDigest[i] ? 1 : 0;
    return mask;
  }, [aDigest, bDigest]);

  const bitD = useMemo(() => bitDiff(aDigest, bDigest), [aDigest, bDigest]);
  const bitR = useMemo(() => bitRatio(aDigest, bDigest), [aDigest, bDigest]);

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--violet)" }}>Lab 03</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">MD5 消息摘要</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          MD5 由 Ron Rivest 于 1991 年设计（RFC 1321），将任意长度的消息压缩为固定 128-bit（16 字节）摘要。
          本页算法完全从零实现：512-bit 分组、四轮 64 步非线性函数与循环移位，不依赖任何库。
          哈希的关键性质是<strong style={{ color: "var(--text)" }}>雪崩效应</strong>——输入哪怕只差一个比特，输出也应面目全非。
        </p>
      </div>

      {/* 实时哈希 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />实时摘要</div>
        <label className="field-label mt-3">输入消息（任意文本）</label>
        <textarea
          className="input min-h-[80px] resize-y"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="输入要计算 MD5 的内容…"
        />
        <div className="mt-4 grid gap-3 md:grid-cols-[auto_1fr]">
          <div className="kv md:w-56"><span className="k">消息长度</span><span className="v">{strToBytes(text).length} B</span></div>
          <div className="kv"><span className="k">MD5 摘要（hex，128 bit）</span><span className="v">{digest}</span></div>
        </div>
      </div>

      {/* 标准向量 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" />RFC 1321 标准向量验证</div>
        <p className="hint mt-1">权威测试用例：实现若正确，下列摘要必须与 RFC 1321 附录一致。</p>
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {[
            ["MD5(\"\")", "d41d8cd98f00b204e9800998ecf8427e"],
            ["MD5(\"abc\")", "900150983cd24fb0d6963f7d28e17f72"],
            ["MD5(\"message digest\")", "f96b697d7cb7938d525a2f31aaf161d0"],
            ["MD5(\"abcdefghijklmnopqrstuvwxyz\")", "c3fcd3d76192e4007dfb496cca67e13b"],
          ].map(([name, ref]) => {
            const mine = md5Hex(strToBytes(name.replace("MD5(", "").replaceAll("\"", "").replace(")", "")));
            const ok = mine === ref;
            return (
              <div key={name as string} className="rounded-lg border p-3" style={{ borderColor: ok ? "rgba(74,222,128,.3)" : "var(--border)" }}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs" style={{ color: "var(--text-dim)" }}>{name}</span>
                  {ok ? <span className="chip">✓ 通过</span> : <span className="chip chip-red">✗ 不符</span>}
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>实现</span>
                  <span className="break-all font-mono text-xs" style={{ color: ok ? "var(--accent)" : "var(--red)" }}>{mine}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px]" style={{ color: "var(--text-faint)" }}>标准</span>
                  <span className="break-all font-mono text-xs" style={{ color: "var(--text-dim)" }}>{ref}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 雪崩效应 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />雪崩效应实验</div>
        <p className="hint mt-1">让两段仅差一个字符的消息分别求摘要，观察输出位差异。</p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <label className="field-label">消息 A</label>
            <input className="input font-mono" value={aText} onChange={(e) => setAText(e.target.value)} />
          </div>
          <div>
            <label className="field-label">消息 B（改一个字符试试）</label>
            <input className="input font-mono" value={bText} onChange={(e) => setBText(e.target.value)} />
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button key={p.label} className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => { setAText(p.a); setBText(p.b); }}>
              {p.label}
            </button>
          ))}
        </div>

        <div className="mt-5 space-y-3 overflow-x-auto rounded-lg border p-4" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
          <ByteRow label="A" bytes={aDigest} diffMask={diff} />
          <ByteRow label="B" bytes={bDigest} diffMask={diff} />
          <p className="hint mt-2">黄色高亮为两摘要不同的字节。理想哈希下 128 bit 中约一半不同。</p>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <div className="kv"><span className="k">差异字节数</span><span className="v">{diff.reduce((s, x) => s + x, 0)} / 16</span></div>
          <div className="kv"><span className="k">差异比特数</span><span className="v">{bitD} / 128</span></div>
          <div className="kv">
            <span className="k">差异比例</span>
            <span className="v">{(bitR * 100).toFixed(1)}%</span>
          </div>
        </div>
        <div className="mt-3 h-2 w-full overflow-hidden rounded-full" style={{ background: "rgba(2,6,17,.8)", border: "1px solid var(--border)" }}>
          <div
            className="h-full rounded-full transition-all"
            style={{
              width: `${Math.max(4, Math.min(100, bitR * 100))}%`,
              background: "linear-gradient(90deg,#4ade80,#fbbf24,#f87171)",
            }}
          />
        </div>
        <p className="hint mt-3">
          {bitR > 0.35 && bitR < 0.65
            ? "✓ 接近理想的 50%：输入的微小变化被充分扩散到整个摘要。"
            : "观察输入差异是否过小（两段几乎相同）——换成仅差一个字符的消息再试。"}
        </p>
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />填充与长度</div>
          <p className="hint mt-2 leading-relaxed">消息末尾补 0x80 与若干 0x00，使总长 ≡ 448 (mod 512)，最后 8 字节记录原始 bit 长度（小端）。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />压缩函数</div>
          <p className="hint mt-2 leading-relaxed">每 512-bit 分组经 4 轮 × 16 步迭代：非线性函数 F/G/H/I、正弦表 T[i]、循环左移 S[i]，更新 4 个 32-bit 状态字。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--amber)", boxShadow: "0 0 8px var(--amber)" }} />安全现状</div>
          <p className="hint mt-2 leading-relaxed">2004 年王小云教授团队给出 MD5 碰撞攻击，如今 MD5 已不适用于签名等安全场景，但仍广泛用于校验和与教学。</p>
        </div>
      </div>
    </div>
  );
}
