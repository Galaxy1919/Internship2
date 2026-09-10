"use client";

import { useState } from "react";
import Link from "next/link";

const C = "#22d3ee";

const MODES = [
  { id: "message", label: "消息加密", desc: "传输密码加密任意消息" },
  { id: "cipher", label: "对称密码", desc: "8 个对称密码任选，信封加密" },
  { id: "pubkey", label: "公钥密码", desc: "RSA/ElGamal/SM2 反向密钥流" },
  { id: "digest", label: "MD5 摘要", desc: "完整性校验" },
  { id: "ecdh", label: "ECDH", desc: "secp256k1 密钥交换" },
  { id: "file", label: "文件传输", desc: "64KB 分块加密传输文件" },
];

function fileToBase64(f: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const s = String(reader.result);
      resolve(s.slice(s.indexOf(",") + 1)); // 去掉 "data:...;base64," 前缀
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(f);
  });
}

const CIPHERS = [
  ["aes", "AES"],
  ["des", "DES"],
  ["rc4", "RC4"],
  ["ca", "CA 元胞自动机"],
  ["vigenere", "Vigenère"],
  ["playfair", "Playfair"],
  ["multiliteral", "多表替代"],
  ["transposition", "列置换"],
] as const;
const PUBKEYS = [
  ["rsa", "RSA"],
  ["elgamal", "ElGamal"],
  ["sm2", "SM2"],
] as const;
const TRANSPORTS = [
  ["aes", "AES"],
  ["des", "DES"],
  ["rc4", "RC4"],
  ["ca", "CA"],
] as const;

const STAGES = ["启动进程", "DH 握手", "派生密钥", "发送数据", "校验结果"];

const BYTES_CIPHERS = new Set(["aes", "des", "rc4", "ca"]);

type Result = {
  ok: boolean;
  clientStdout: string;
  clientStderr: string;
  serverOutput: string;
  error?: string;
};

export default function DualPage() {
  const [mode, setMode] = useState("message");
  const [cipher, setCipher] = useState("aes");
  const [transport, setTransport] = useState("aes");
  const [text, setText] = useState("HELLO WORLD");
  const [key, setKey] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);

  const needCipher = mode === "cipher" || mode === "pubkey";

  async function run() {
    setLoading(true);
    setResult(null);
    try {
      let payload: Record<string, unknown> = { mode, cipher, transport, text, key: key || undefined };
      if (mode === "file") {
        if (!file) {
          setResult({ ok: false, clientStdout: "", clientStderr: "", serverOutput: "", error: "请先选择要传输的文件" });
          return;
        }
        const content = await fileToBase64(file);
        payload = { mode: "file", filename: file.name, content, transport };
      }
      const res = await fetch("/api/dual/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = (await res.json()) as Result;
      setResult(data);
    } catch (e) {
      setResult({ ok: false, clientStdout: "", clientStderr: "", serverOutput: "", error: String(e) });
    } finally {
      setLoading(false);
    }
  }

  // ---- 一致性校验（从两端输出里提取）----
  const clientDh = result?.clientStdout?.match(/DH_SHARED (\d+)/)?.[1];
  const serverDh = result?.serverOutput?.match(/DH_SHARED (\d+)/)?.[1];
  const dhOk = !!(clientDh && serverDh && clientDh === serverDh);

  const serverPlain = result?.serverOutput?.match(/PLAINTEXT (.*)/)?.[1];
  const strictPlain = (mode === "message" || (mode === "cipher" && BYTES_CIPHERS.has(cipher)));
  const plainOk = strictPlain ? serverPlain === text : undefined;

  const digestOk = mode === "digest" ? result?.serverOutput?.includes("DIGEST_MATCH PASS") : undefined;

  const clientEcdh = result?.clientStdout?.match(/ECDH_SHARED ([0-9a-f]+)/)?.[1];
  const serverEcdh = result?.serverOutput?.match(/ECDH_SHARED ([0-9a-f]+)/)?.[1];
  const ecdhOk = mode === "ecdh" ? !!(clientEcdh && serverEcdh && clientEcdh === serverEcdh) : undefined;

  const clientFileSize = result?.clientStdout?.match(/FILE_SIZE (\d+)/)?.[1];
  const serverFileSize = result?.serverOutput?.match(/FILE_SIZE (\d+)/)?.[1];
  const fileOk = mode === "file" ? !!(clientFileSize && serverFileSize && clientFileSize === serverFileSize) : undefined;
  const fileSaved = result?.serverOutput?.match(/FILE_SAVED (.*)/)?.[1];
  const stageDone = result?.ok ? STAGES.length : loading ? 3 : result ? 2 : 0;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <Link href="/" className="text-xs" style={{ color: "var(--text-faint)" }}>
            ← 首页
          </Link>
          <span className="font-mono text-xs font-bold tracking-widest" style={{ color: C }}>
            双机 · Socket 通信
          </span>
        </div>
        <h1 className="mt-2 text-3xl font-black tracking-tight">双机加解密</h1>
        <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
          两个 Python 进程在 Socket 上完成{" "}
          <strong style={{ color: "var(--text)" }}>DH 密钥协商 → 传输密码加密 → 解密端还原</strong>。
          前端不重写算法，而是调用 Python CLI 作为后端（本机模拟双机：加密端 Alice ↔ 解密端 Bob）。
        </p>
      </div>

      {/* 控制面板 */}
      <div className="panel p-5">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="field-label">模式</label>
            <div className="flex flex-wrap gap-1.5">
              {MODES.map((m) => (
                <button
                  key={m.id}
                  onClick={() => setMode(m.id)}
                  title={m.desc}
                  className={`btn ${mode === m.id ? "btn-primary" : "btn-ghost"} !px-3 !py-1.5 text-xs`}
                >
                  {m.label}
                </button>
              ))}
            </div>
            <label className="field-label mt-4">传输密码（密钥由 DH 派生）</label>
            <div className="flex flex-wrap gap-1.5">
              {TRANSPORTS.map(([id, label]) => (
                <button
                  key={id}
                  onClick={() => setTransport(id)}
                  className={`btn ${transport === id ? "btn-primary" : "btn-ghost"} !px-3 !py-1.5 text-xs`}
                >
                  {label}
                </button>
              ))}
            </div>
            <p className="hint mt-2">
              传输密码加密整个信封，网络上传的永远是密文。任意传输密码都消费 DH 派生的密钥，满足「至少一个密码用 DH 换密钥」。
            </p>
          </div>

          <div>
            {needCipher && (
              <>
                <label className="field-label">{mode === "cipher" ? "对称密码算法" : "公钥密码算法"}</label>
                <div className="flex flex-wrap gap-1.5">
                  {(mode === "cipher" ? CIPHERS : PUBKEYS).map(([id, label]) => (
                    <button
                      key={id}
                      onClick={() => setCipher(id)}
                      className={`btn ${cipher === id ? "btn-primary" : "btn-ghost"} !px-3 !py-1.5 text-xs`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </>
            )}
            {mode === "cipher" && (
              <>
                <label className="field-label mt-4">密钥（可选，缺省自动生成）</label>
                <input
                  className="input font-mono"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="留空 = 自动生成密钥"
                />
              </>
            )}
            {mode === "file" ? (
              <>
                <label className="field-label mt-4">选择要传输的文件</label>
                <input
                  type="file"
                  className="input"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                {file && (
                  <p className="hint mt-2">已选：{file.name}（{file.size} 字节）</p>
                )}
                <p className="hint mt-2">
                  文件经 64KB 分块 + 传输密码加密 + HMAC 校验后发送，Bob 解密后保存到 DH/received/。
                </p>
              </>
            ) : (
              <>
                <label className="field-label mt-4">明文</label>
                <textarea
                  className="input min-h-[80px] resize-y"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="输入要加密的消息…"
                />
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <button className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => setText("HELLO WORLD")}>
                    英文示例
                  </button>
                  <button className="btn-ghost btn !px-2.5 !py-1 text-xs" onClick={() => setText("双机加解密演示：信息安全实训 2026")}>
                    中文示例
                  </button>
                </div>
                <p className="hint mt-2">
                  古典密码（Vigenère/Playfair/多表/列置换）只处理 A–Z 字母；AES/DES/RC4/CA 及公钥密码、MD5 支持任意文本（含中文）。
                </p>
              </>
            )}
          </div>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <button className="btn btn-primary" onClick={run} disabled={loading}>
            {loading ? "运行中…" : "运行双机加解密"}
          </button>
          {result && !loading && (
            <span className={`chip ${result.ok ? "" : "chip-red"}`}>{result.ok ? "✓ 完成" : "✗ 失败"}</span>
          )}
        </div>
        {result?.error && (
          <p className="mt-3 text-xs" style={{ color: "var(--red)" }}>
            ⚠ {result.error}
          </p>
        )}
      </div>

      {(loading || result) && (
        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: loading ? "var(--amber)" : result?.ok ? C : "var(--red)", boxShadow: "none" }} />
            运行阶段
            <span className="ml-auto font-mono text-xs font-normal" style={{ color: "var(--text-faint)" }}>
              {loading ? "处理中" : result?.ok ? "完成" : "失败"}
            </span>
          </div>
          <div className="mt-4 grid gap-2 md:grid-cols-5">
            {STAGES.map((stage, i) => {
              const done = i < stageDone;
              const active = loading && i === stageDone;
              return (
                <div
                  key={stage}
                  className="rounded-md border px-3 py-2"
                  style={{
                    borderColor: done || active ? "rgba(74,222,128,.34)" : "var(--border)",
                    background: done || active ? "rgba(74,222,128,.06)" : "rgba(2,6,17,.35)",
                  }}
                >
                  <div className="font-mono text-[11px]" style={{ color: done || active ? "var(--accent)" : "var(--text-faint)" }}>
                    {String(i + 1).padStart(2, "0")}
                  </div>
                  <div className="mt-1 text-sm font-medium">{stage}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 一致性校验 */}
      {result?.ok && (
        <div className="panel p-5">
          <div className="panel-title">
            <span className="dot" style={{ background: C, boxShadow: `0 0 8px ${C}` }} />
            一致性校验
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            <span className={`chip ${dhOk ? "" : "chip-red"}`}>
              {dhOk ? "✓ DH 共享密钥一致" : "✗ DH 共享密钥不一致"}
            </span>
            {plainOk !== undefined && (
              <span className={`chip ${plainOk ? "" : "chip-red"}`}>
                {plainOk ? "✓ 明文还原一致" : "✗ 明文还原不一致"}
              </span>
            )}
            {digestOk !== undefined && (
              <span className={`chip ${digestOk ? "" : "chip-red"}`}>
                {digestOk ? "✓ 摘要校验一致" : "✗ 摘要校验不一致"}
              </span>
            )}
            {ecdhOk !== undefined && (
              <span className={`chip ${ecdhOk ? "" : "chip-red"}`}>
                {ecdhOk ? "✓ ECDH 共享点一致" : "✗ ECDH 共享点不一致"}
              </span>
            )}
            {fileOk !== undefined && (
              <span className={`chip ${fileOk ? "" : "chip-red"}`}>
                {fileOk ? "✓ 文件大小一致" : "✗ 文件大小不一致"}
              </span>
            )}
            {fileSaved && <span className="chip">保存到 {fileSaved}</span>}
          </div>
        </div>
      )}

      {/* 输出分栏 */}
      {result && (
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="panel p-5">
            <div className="panel-title">
              <span className="dot" style={{ background: "#4ade80", boxShadow: "0 0 8px #4ade80" }} />
              加密端 Alice（encrypt_client.py）
            </div>
            <pre
              className="mt-3 max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded-lg border p-3 font-mono text-xs leading-relaxed"
              style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.7)", color: "var(--text)" }}
            >
              {result.clientStdout || result.clientStderr || "(无输出)"}
            </pre>
          </div>
          <div className="panel p-5">
            <div className="panel-title">
              <span className="dot" style={{ background: "#22d3ee", boxShadow: "0 0 8px #22d3ee" }} />
              解密端 Bob（decrypt_server.py）
            </div>
            <pre
              className="mt-3 max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded-lg border p-3 font-mono text-xs leading-relaxed"
              style={{ borderColor: "var(--border)", background: "rgba(2,6,17,.7)", color: "var(--text)" }}
            >
              {result.serverOutput || "(无输出)"}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
