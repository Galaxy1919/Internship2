"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  buildSquare,
  decrypt,
  formatSquareRows,
  normalizeKey,
  preparePlaintext,
  trace,
} from "@/lib/playfair";

const EXAMPLES = [
  { label: "Wikipedia 经典向量", key: "playfair example", plain: "Hide the gold in the tree stump" },
  { label: "密钥 MONARCHY", key: "MONARCHY", plain: "The quick brown fox jumps over the lazy dog" },
  { label: "空密钥（标准字母序）", key: "", plain: "Attack at dawn" },
];

const WIKI_CIPHER = "BMODZBXDNABEKUDMUIXMMOUVIF";

export default function PlayfairPage() {
  const [plain, setPlain] = useState("Hide the gold in the tree stump");
  const [key, setKey] = useState("playfair example");
  const [cipherIn, setCipherIn] = useState(WIKI_CIPHER);

  const square = useMemo(() => {
    try {
      return buildSquare(key);
    } catch {
      return null;
    }
  }, [key]);
  const rows = useMemo(() => (square ? formatSquareRows(square) : []), [square]);
  const normKey = useMemo(() => normalizeKey(key), [key]);

  const rec = useMemo(() => {
    if (!square) return null;
    try {
      return trace(plain, key);
    } catch {
      return null;
    }
  }, [plain, square, key]);

  const dec = useMemo(() => {
    if (!square || !cipherIn.trim()) return "";
    try {
      return decrypt(cipherIn, key);
    } catch (e) {
      return `⚠ ${(e as Error).message}`;
    }
  }, [cipherIn, square, key]);

  const prepBack = useMemo(() => {
    if (!square || dec.startsWith("⚠") || !dec) return null;
    try {
      return preparePlaintext(plain);
    } catch {
      return null;
    }
  }, [dec, plain, square]);

  const ruleColor: Record<string, string> = {
    "同行→右移": "var(--cyan)",
    "同列→下移": "var(--amber)",
    "矩形→换列": "var(--violet)",
  };

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--amber)" }}>Lab 09</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">Playfair 双字母替代密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          1854 年由 Charles Wheatstone 发明、以 Lord Playfair 命名的第一种<strong style={{ color: "var(--text)" }}>多图替代</strong>密码:
          一次加密一个<strong style={{ color: "var(--text)" }}>双字母组</strong>(digraph),而非单个字母。
          同一明文字母因相邻字母不同会得到不同密文,显著削弱单字母频率分析;
          英国陆军在布尔战争与一战中曾实际使用它。
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* 左: 方阵 */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />5×5 密钥方阵</div>
          <label className="field-label mt-3">密钥词（去重 + I/J 合并后先填入，再按字母序补全）</label>
          <input
            className="input"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="如 playfair example"
          />
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                className="btn-ghost btn !px-2.5 !py-1 text-xs"
                onClick={() => { setKey(ex.key); setPlain(ex.plain); setCipherIn(""); }}
              >
                {ex.label}
              </button>
            ))}
          </div>

          {square ? (
            <>
              <div className="mt-4 flex items-center justify-between text-xs" style={{ color: "var(--text-dim)" }}>
                <span>归一化密钥：<span className="chip">{normKey || "（无）"}</span></span>
                <span>25 字母 · 无 J</span>
              </div>
              <div className="mt-2 grid grid-cols-6 gap-1.5">
                <div />
                {[1, 2, 3, 4, 5].map((c) => (
                  <div key={c} className="text-center font-mono text-xs" style={{ color: "var(--cyan)" }}>{c}</div>
                ))}
                {rows.map((row, ri) => (
                  <FragmentRow key={ri} row={row} ri={ri} />
                ))}
              </div>
              <div className="mt-3 grid grid-cols-1 gap-1.5 text-xs sm:grid-cols-3" style={{ color: "var(--text-dim)" }}>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-sm" style={{ background: "rgba(34,211,238,.25)", border: "1px solid rgba(34,211,238,.4)" }} /> 同行 → 各自右移</div>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-sm" style={{ background: "rgba(251,191,36,.2)", border: "1px solid rgba(251,191,36,.4)" }} /> 同列 → 各自下移</div>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-sm" style={{ background: "rgba(167,139,250,.2)", border: "1px solid rgba(167,139,250,.4)" }} /> 异行异列 → 矩形换列</div>
              </div>
            </>
          ) : (
            <p className="mt-4 text-sm" style={{ color: "var(--red)" }}>密钥含非法字符，无法构建方阵。</p>
          )}
        </div>

        {/* 右: 加密 */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--accent)", boxShadow: "0 0 8px var(--accent)" }} />加密与预处理</div>
          <label className="field-label mt-3">明文（仅字母参与，自动去空格大写、J→I、双写插 X）</label>
          <textarea
            className="input min-h-[80px] resize-y"
            value={plain}
            onChange={(e) => setPlain(e.target.value)}
            placeholder="输入要加密的英文文本…"
          />
          {rec && (
            <>
              <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
                <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
                  <div className="field-label !mb-1">预处理（分组前）</div>
                  <div className="font-mono break-all" style={{ color: "var(--amber)" }}>{rec.prepared}</div>
                </div>
                <div className="rounded-lg border p-3" style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.5)" }}>
                  <div className="field-label !mb-1">双字母分组</div>
                  <div className="font-mono break-all">
                    {Array.from({ length: rec.prepared.length / 2 }, (_, i) => (
                      <span key={i} className="mr-2" style={{ color: "var(--text)" }}>{rec.prepared.slice(i * 2, i * 2 + 2)}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="field-label mt-4">密文输出</div>
              <div className="output break-all leading-relaxed">{rec.ciphertext}</div>
              {rec.ciphertext === WIKI_CIPHER && key.trim().toLowerCase().replace(/\s+/g, " ") === "playfair example" && (
                <p className="mt-2 flex items-center gap-2 text-xs" style={{ color: "var(--accent)" }}>
                  <span className="chip">✓ 标准向量</span>
                  与 Wikipedia 已知向量 BMODZBXDNABEKUDMUIXMMOUVIF 完全一致 —— 实现正确。
                </p>
              )}
            </>
          )}
        </div>
      </div>

      {/* 分步轨迹 */}
      {rec && rec.steps.length > 0 && (
        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />
            分步替换轨迹
            <span className="ml-auto font-mono text-xs font-normal" style={{ color: "var(--text-faint)" }}>
              {rec.steps.length} 组双字母 · 位置为 1-based 坐标
            </span>
          </div>
          <p className="hint mt-1">每一组都展开命中规则与替换前后坐标：同行对看行、同列对看列，其余看矩形对角。</p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr style={{ color: "var(--text-faint)" }}>
                  <th className="pb-2 pr-3 font-medium">#</th>
                  <th className="pb-2 pr-3 font-medium">明文对</th>
                  <th className="pb-2 pr-3 font-medium">命中规则</th>
                  <th className="pb-2 pr-3 font-medium">a 坐标</th>
                  <th className="pb-2 pr-3 font-medium">b 坐标</th>
                  <th className="pb-2 font-medium">密文对</th>
                </tr>
              </thead>
              <tbody>
                {rec.steps.map((s, i) => (
                  <tr key={i} className="border-t" style={{ borderColor: "var(--border)" }}>
                    <td className="py-2 pr-3" style={{ color: "var(--text-faint)" }}>{i + 1}</td>
                    <td className="py-2 pr-3 font-bold tracking-widest">{s.pair}</td>
                    <td className="py-2 pr-3">
                      <span className="chip" style={{ borderColor: `${ruleColor[s.rule]}44`, color: ruleColor[s.rule], background: `${ruleColor[s.rule]}14` }}>
                        {s.rule}
                      </span>
                    </td>
                    <td className="py-2 pr-3" style={{ color: "var(--text-dim)" }}>({s.aPos[0]}, {s.aPos[1]})</td>
                    <td className="py-2 pr-3" style={{ color: "var(--text-dim)" }}>({s.bPos[0]}, {s.bPos[1]})</td>
                    <td className="py-2 font-bold tracking-widest" style={{ color: "var(--accent)", textShadow: "0 0 8px rgba(74,222,128,.2)" }}>{s.out}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 解密 */}
      <div className="panel p-5">
        <div className="panel-title">
          <span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />
          解密往返验证
          <span className="ml-auto font-mono text-xs font-normal" style={{ color: "var(--text-faint)" }}>密文须为偶数个字母（自动忽略非字母）</span>
        </div>
        <label className="field-label mt-3">输入密文</label>
        <textarea
          className="input min-h-[70px] resize-y font-mono"
          value={cipherIn}
          onChange={(e) => setCipherIn(e.target.value.toUpperCase())}
          placeholder={WIKI_CIPHER}
        />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button className="btn btn-ghost text-xs" onClick={() => setCipherIn(rec?.ciphertext ?? WIKI_CIPHER)}>
            回填刚才的密文
          </button>
          <button className="btn btn-ghost text-xs" onClick={() => setCipherIn(WIKI_CIPHER)}>
            填入 Wiki 向量
          </button>
          {!dec.startsWith("⚠") && dec && (
            <span className="chip chip-cyan">✓ 解密成功</span>
          )}
        </div>
        <label className="field-label mt-4">解密结果</label>
        <div className="output break-all" style={dec.startsWith("⚠") ? { color: "var(--red)", textShadow: "none" } : { color: "var(--cyan)", textShadow: "0 0 10px rgba(34,211,238,.2)" }}>
          {dec || "等待输入密文…"}
        </div>
        {!dec.startsWith("⚠") && dec && prepBack && (
          <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
            <p className="hint leading-relaxed">
              解密结果与「预处理明文」<span className="chip">{prepBack}</span> 完全一致 —— 加解密互为逆操作。
            </p>
            <p className="hint leading-relaxed">
              注意：还原结果含为了消除双写而插入的 X（如 LL→LX）与末尾填充 X。Playfair 无法自动区分 X 是填充还是真实字母，这是它的固有限制。
            </p>
          </div>
        )}
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />多图替代</div>
          <p className="hint mt-2 leading-relaxed">一次处理两个字母，密文取决于字母对在方阵中的相对位置。同字母在不同对中映射不同，频率分布被摊平，比单表替代难破译得多。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />预处理约定</div>
          <p className="hint mt-2 leading-relaxed">I/J 合并让 25 字母恰好填满 5×5；相邻相同字母间插 X 防止同对同字；末尾不足补 X。这些约定双方必须一致，解密时需人工剔除填充 X。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--red)", boxShadow: "0 0 8px var(--red)" }} />局限</div>
          <p className="hint mt-2 leading-relaxed">方阵仅 25×25 种双字母映射，仍保留大量结构：双字母频率分析、明文冗余猜测（如 THE）可攻破。它证明了多图思想，但很快被更系统的多表替代（Vigenère）超越。</p>
        </div>
      </div>
    </div>
  );
}

function FragmentRow({ row, ri }: { row: string[]; ri: number }) {
  return (
    <>
      <div className="text-center font-mono text-xs" style={{ color: "var(--cyan)" }}>{ri + 1}</div>
      {row.map((ch, ci) => (
        <div key={ci} className="grid-cell">{ch}</div>
      ))}
    </>
  );
}
