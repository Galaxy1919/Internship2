"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  columnOrder,
  transEncrypt,
  transDecrypt,
  transEncryptBytes,
  transDecryptBytes,
  traceMatrix,
} from "@/lib/transposition";
import { strToBytes, bytesToHex, hexToBytes, bytesToStr } from "@/lib/bytes";

const EXAMPLES = [
  { key: "ZEBRA", plain: "WE ARE DISCOVERED FLEE AT ONCE" },
  { key: "SECRET", plain: "THIS IS A SECRET MESSAGE" },
  { key: "密钥", plain: "列置换支持中文密文" },
];

export default function TranspositionPage() {
  const [plain, setPlain] = useState("WE ARE DISCOVERED FLEE AT ONCE");
  const [key, setKey] = useState("ZEBRA");
  const [cipherHex, setCipherHex] = useState("");
  const [mode, setMode] = useState<"enc" | "dec">("enc");

  // trace 需要字符级；密文是字节级 hex，展示时映射回字符
  const trace = useMemo(() => {
    try {
      return traceMatrix(plain, key);
    } catch {
      return null;
    }
  }, [plain, key]);

  const order = useMemo(() => {
    try {
      return columnOrder(key);
    } catch {
      return null;
    }
  }, [key]);

  const bytes = useMemo(() => strToBytes(plain), [plain]);

  const enc = useMemo(() => {
    try {
      return transEncrypt(plain, key);
    } catch {
      return null;
    }
  }, [plain, key]);

  const encHex = useMemo(() => (enc ? bytesToHex(enc) : ""), [enc]);
  // 尝试把密文字节解码回可打印文本（仅当密文恰好是合法 UTF-8 时有效）
  const encText = useMemo(() => {
    if (!enc) return "";
    const t = bytesToStr(enc);
    // 可打印检测：不含控制字符
    return /^[\x20-\x7e\u4e00-\u9fff\uff00-\uffef，。！？、；：""''（）\s]*$/.test(t) ? t : "";
  }, [enc]);

  const decResult = useMemo(() => {
    try {
      if (!cipherHex.trim()) return { ok: true as const, text: "" };
      const c = hexToBytes(cipherHex);
      return { ok: true as const, text: bytesToStr(transDecryptBytes(c, key)) };
    } catch (e) {
      return { ok: false as const, text: (e as Error).message };
    }
  }, [cipherHex, key]);

  // 密钥排序后的列读取顺序（展示用，字符序）
  const width = [...key].length;
  const readOrderStr = order ? order.map((i) => i + 1).join(" → ") : "";
  const keySorted = useMemo(() => {
    if (!order) return "";
    return order.map((i) => [...key][i]).join("");
  }, [order, key]);

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/single" className="text-xs" style={{ color: "var(--text-faint)" }}>← 单机实验</Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: "var(--cyan)" }}>Lab 02</span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">列置换密码</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          换位密码（Transposition）不替换字母本身，而是打乱字母的位置。列置换按密钥宽度把明文逐行写入矩阵，
          然后按密钥字母排序后的列顺序读出，得到密文。本实现工作在字节层面，因此中英文混排也能正确加解密。
        </p>
      </div>

      {/* 输入 */}
      <div className="panel p-5">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label">明文</label>
            <textarea
              className="input min-h-[100px] resize-y"
              value={plain}
              onChange={(e) => setPlain(e.target.value)}
              placeholder="输入要加密的文本…"
            />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.key}
                  className="btn-ghost btn !px-2.5 !py-1 text-xs"
                  onClick={() => { setKey(ex.key); setPlain(ex.plain); setMode("enc"); }}
                >
                  {ex.key} / {ex.plain.slice(0, 12)}…
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="field-label">密钥（列数 = 密钥长度，字符需不重复）</label>
            <input
              className="input"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="如 ZEBRA、SECRET…"
            />
            {order ? (
              <div className="mt-3 space-y-2">
                <div className="kv"><span className="k">密钥长度（列数）</span><span className="v">{width}</span></div>
                <div className="kv"><span className="k">密钥字母排序</span><span className="v">{keySorted}</span></div>
                <div className="kv"><span className="k">列读取顺序</span><span className="v">{readOrderStr}</span></div>
              </div>
            ) : (
              <p className="mt-3 text-sm" style={{ color: "var(--red)" }}>
                {key ? "密钥含重复字符或为空 —— 为避免列编号歧义请使用不重复字符。" : "请输入密钥"}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* 矩阵可视化 */}
      {trace && order && (
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />矩阵写入与列序读出</div>
          <div className="mt-3 overflow-x-auto">
            <div className="mx-auto" style={{ minWidth: width * 46 }}>
              {/* 密钥行 */}
              <div className="flex">
                {[...key].map((ch, i) => (
                  <div key={i} className="grid-cell head mx-[3px] font-bold">{ch}</div>
                ))}
              </div>
              {/* 排序编号行 */}
              <div className="mt-1 flex">
                {trace.columnNumbers.map((n, i) => {
                  const readAt = order.indexOf(i);
                  return (
                    <div key={i} className="mx-[3px] flex h-6 flex-1 items-center justify-center font-mono text-[11px]" style={{ color: readAt >= 0 ? "var(--accent)" : "var(--text-faint)" }}>
                      {readAt >= 0 ? `#${readAt + 1}` : ""}
                    </div>
                  );
                })}
              </div>
              {/* 矩阵内容 */}
              {trace.matrixRows.map((row, ri) => (
                <div key={ri} className="mt-1 flex">
                  {row.map((ch, ci) => (
                    <div key={ci} className="grid-cell mx-[3px]">{ch === " " ? "␣" : ch}</div>
                  ))}
                </div>
              ))}
            </div>
          </div>
          <p className="hint mt-3">
            上方第一行是密钥（宽度 = 列数），第二行数字表示按密钥字母排序后每列的读取次序。加密时按 <span style={{ color: "var(--accent)" }}>#1 → #2 → …</span> 顺序逐列读出全部字符。
          </p>
        </div>
      )}

      {/* 结果 */}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />加密结果</div>
          <div className="mt-3 flex items-center gap-2">
            <div className="kv flex-1"><span className="k">字节长度</span><span className="v">{bytes.length} B</span></div>
            <div className="kv flex-1"><span className="k">原始明文</span><span className="v">{plain.length} 字符</span></div>
          </div>
          {encText ? (
            <>
              <label className="field-label mt-4">密文（文本形式）</label>
              <div className="output min-h-[52px]">{encText}</div>
            </>
          ) : (
            <p className="hint mt-3">密文为不可打印字节（多字节 UTF-8 被打散），请用下方 hex 形式查看或直接解密回明文。</p>
          )}
          <label className="field-label mt-4">密文（hex）</label>
          <div className="output min-h-[52px] break-all">{encHex || "—"}</div>
          <div className="mt-3 flex gap-2">
            <button
              className="btn btn-ghost text-xs"
              onClick={() => {
                setCipherHex(encHex);
                setMode("dec");
              }}
            >
              用此密文去解密
            </button>
            <button
              className="btn btn-ghost text-xs"
              onClick={() => {
                // 自校验：解密应还原明文
                try {
                  const back = bytesToStr(transDecryptBytes(enc!, key));
                  alert(back === plain ? "✓ 解密成功，与原文完全一致" : `✗ 不一致：${back}`);
                } catch { /* ignore */ }
              }}
            >
              自校验
            </button>
          </div>
        </div>

        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />解密</div>
          <label className="field-label mt-3">密文（hex 或上方自动回填）</label>
          <textarea
            className="input min-h-[90px] resize-y font-mono"
            value={cipherHex}
            onChange={(e) => setCipherHex(e.target.value)}
            placeholder="粘贴 hex 密文…"
          />
          {!decResult.ok && (
            <p className="mt-2 text-xs" style={{ color: "var(--red)" }}>⚠ {decResult.text}</p>
          )}
          <label className="field-label mt-4">解密明文</label>
          <div className="output min-h-[52px]">{decResult.text || "等待密文…"}</div>
          {decResult.ok && decResult.text && mode === "dec" && (
            <p className="hint mt-2">
              {decResult.text === plain ? "✓ 解密结果与原文一致" : "（与当前明文字段不同，属正常——解密按密文内容独立进行）"}
            </p>
          )}
        </div>
      </div>

      {/* 原理说明 */}
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" />换位思想</div>
          <p className="hint mt-2 leading-relaxed">字母频率保持不变，但位置被打乱。这破坏了连续字母组合（双字母组、三字母组）的统计规律。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--cyan)", boxShadow: "0 0 8px var(--cyan)" }} />密钥即宽度</div>
          <p className="hint mt-2 leading-relaxed">密钥长度决定矩阵宽度，密钥字母的字典序决定列读取顺序——同一把密钥同时携带「宽多少」和「怎么读」两个信息。</p>
        </div>
        <div className="panel p-5">
          <div className="panel-title"><span className="dot" style={{ background: "var(--violet)", boxShadow: "0 0 8px var(--violet)" }} />末行不补齐</div>
          <p className="hint mt-2 leading-relaxed">本实现采用变长列布局：最后一行不满时直接截断，无需填充伪字符，密文长度与明文严格一致。</p>
        </div>
      </div>
    </div>
  );
}
