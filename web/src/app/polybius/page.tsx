"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  buildSquare,
  buildTables,
  polybiusEncrypt,
  polybiusDecrypt,
  formatSquareRows,
  normalizeKey,
} from "@/lib/polybius";

const EXAMPLES = [
  { label: "标准方阵（无关键字）", key: "", plain: "HELLO WORLD" },
  { label: "关键字 CIPHER", key: "CIPHER", plain: "DEFEND THE EAST WALL" },
  { label: "含 J 自动转 I", key: "KEY", plain: "JULIUS CAESAR" },
];

export default function PolybiusPage() {
  const [plain, setPlain] = useState("DEFEND THE EAST WALL");
  const [key, setKey] = useState("CIPHER");
  const [cipherIn, setCipherIn] = useState("");
  const [useSep, setUseSep] = useState(true);

  const sep = useSep ? " " : "";

  const square = useMemo(() => {
    try {
      return buildSquare(key);
    } catch {
      return null;
    }
  }, [key]);

  const rows = useMemo(() => (square ? formatSquareRows(square) : []), [square]);
  const tables = useMemo(() => (square ? buildTables(square) : null), [square]);

  const normKey = useMemo(() => normalizeKey(key), [key]);

  const enc = useMemo(() => {
    try {
      return square ? polybiusEncrypt(plain, key, sep) : null;
    } catch {
      return null;
    }
  }, [plain, square, key, sep]);

  const dec = useMemo(() => {
    try {
      return square && cipherIn.trim() ? polybiusDecrypt(cipherIn, key) : "";
    } catch (e) {
      return `⚠ ${(e as Error).message}`;
    }
  }, [cipherIn, square, key]);

  return (
    <div className="space-y-8">
      {/* 头部 */}
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>← 总览</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--accent)" }}>Lab 01</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">Polybius 方阵密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          公元前二世纪，希腊历史学家 Polybius 提出用 5×5 表格编码字母：每个字母对应「行号+列号」两个数字。
          由于 I 与 J 合并，25 个字母恰好填满方阵；配合关键字打乱字母顺序，可以构成带密钥的单表替代。
          输出形态从「字母」变为「数字」，是古典密码走向多字符编码的重要一步。
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* 左：方阵可视化 */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />5×5 方阵构建</div>
          <label className="field-label mt-3">关键字（可选，用于打乱字母顺序）</label>
          <input
            className="input"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="如 CIPHER，留空则用标准字母序"
          />
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                className="btn-ghost btn !px-2.5 !py-1 text-xs"
                onClick={() => { setKey(ex.key); setPlain(ex.plain); }}
              >
                {ex.label}
              </button>
            ))}
          </div>

          {square ? (
            <>
              <div className="mt-4 flex items-center justify-between text-xs" style={{ color: "var(--text-dim)" }}>
                <span>已归一化关键字：<span className="chip">{normKey || "（无）"}</span></span>
                <span>方阵 = 关键字去重 + 剩余字母表</span>
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
              <p className="hint mt-3">
                行、列坐标从 1 开始编号。加密时把明文字母换成「行号列号」；关键字中的字母会被优先排入方阵，J 自动并入 I。
              </p>
            </>
          ) : (
            <p className="mt-4 text-sm" style={{ color: "var(--red)" }}>关键字包含非法字符，无法构建方阵。</p>
          )}
        </div>

        {/* 右：加密 */}
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />加密</div>
          <label className="field-label mt-3">明文（仅字母参与编码，其余字符自动忽略）</label>
          <textarea
            className="input min-h-[90px] resize-y"
            value={plain}
            onChange={(e) => setPlain(e.target.value)}
            placeholder="输入要加密的英文文本…"
          />
          <div className="mt-2 flex items-center gap-2">
            <span className="field-label !mb-0">数字分隔</span>
            <button
              className={`btn !px-3 !py-1 text-xs ${useSep ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setUseSep(true)}
            >
              空格
            </button>
            <button
              className={`btn !px-3 !py-1 text-xs ${!useSep ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setUseSep(false)}
            >
              紧凑
            </button>
          </div>
          <label className="field-label mt-4">密文（坐标序列）</label>
          <div className="output min-h-[64px] leading-relaxed">{enc ?? "—"}</div>

          {tables && enc && (
            <div className="mt-4">
              <div className="field-label">逐步对照（前 12 个有效字母）</div>
              <div className="flex flex-wrap gap-1.5">
                {Array.from(plain.toUpperCase())
                  .map((c) => (c === "J" ? "I" : c))
                  .filter((c) => tables.encode[c])
                  .slice(0, 12)
                  .map((c, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <span className="grid-cell !h-8 !min-w-[2.4rem] hl">{c}</span>
                      <span className="font-mono text-xs" style={{ color: "var(--text-faint)" }}>→</span>
                      <span className="chip chip-cyan">{tables.encode[c]}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 解密 */}
      <div className="panel p-5">
        <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />解密验证</div>
        <label className="field-label mt-3">输入坐标密文（如 14 15 21 24 15 42 …），自动忽略非数字字符</label>
        <textarea
          className="input min-h-[70px] resize-y font-mono"
          value={cipherIn}
          onChange={(e) => setCipherIn(e.target.value)}
          placeholder="粘贴上方密文试试…"
        />
        <div className="mt-2 flex items-center gap-2">
          <button
            className="btn btn-ghost text-xs"
            onClick={() => setCipherIn(enc ?? "")}
          >
            回填刚才的密文
          </button>
          {enc && (
            <button
              className="btn btn-ghost text-xs"
              onClick={() => {
                const r = polybiusDecrypt(enc, key);
                setPlain(r);
              }}
            >
              解密并写回明文
            </button>
          )}
        </div>
        <label className="field-label mt-4">解密结果</label>
        <div className={`output ${dec.startsWith("⚠") ? "" : ""}`} style={dec.startsWith("⚠") ? { color: "var(--red)", textShadow: "none" } : undefined}>
          {dec || "等待输入密文…"}
        </div>
        {!dec.startsWith("⚠") && dec && (
          <p className="hint mt-2">✓ 坐标经方阵反查字母即得明文 —— 加解密互为逆过程。</p>
        )}
      </div>

      {/* 原理 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />编码表</div>
          <p className="hint mt-2 leading-relaxed">
            不使用 26 字母表，而是 5×5=25 格：I/J 视为同一字母。每个字母被编码为两个十进制数字（行、列各 1-5）。
          </p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />密钥化</div>
          <p className="hint mt-2 leading-relaxed">
            关键字去重后先填入方阵，再按字母序补全剩余字母。知道关键字的双方才拥有同一张表，不知道的人面对的是 25! 种可能排列。
          </p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />局限</div>
          <p className="hint mt-2 leading-relaxed">
            仍是单表替换：同一字母恒映射到同一坐标，频率分析依然有效——这也是后续多表替代与换位密码要解决的问题。
          </p>
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
