import Link from "next/link";

export default function Home() {
  return (
    <div>
      <section className="border-b py-10" style={{ borderColor: "var(--border)" }}>
        <div
          className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-xs"
          style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}
        >
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: "var(--accent)", boxShadow: "0 0 6px var(--accent)" }}
          />
          密码学实训 · 双模式实验平台
        </div>
        <h1 className="mt-6 max-w-3xl text-4xl font-black leading-tight tracking-tight sm:text-5xl">
          密码学实验演示
          <br />
          <span style={{ color: "var(--accent)" }}>
            单机 · 双机
          </span>
        </h1>
        <p className="mt-5 max-w-2xl text-base leading-relaxed" style={{ color: "var(--text-dim)" }}>
          选择一种实验模式：单机在浏览器端从零实现每个算法；双机则通过 Python 后端在两个进程间做密钥协商与加密传输。
        </p>
      </section>

      <section className="mt-8 grid gap-4 sm:grid-cols-2">
        <Link
          href="/single"
          className="group panel relative overflow-hidden p-8 transition hover:-translate-y-0.5"
        >
          <div className="font-mono text-xs tracking-[0.2em]" style={{ color: "var(--accent)" }}>LOCAL / BROWSER</div>
          <h2 className="mt-4 text-2xl font-bold">单机实验</h2>
          <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
            十四个密码学算法，浏览器端纯 TypeScript 从零实现，交互式逐步演示——古典密码、哈希、流密码、分组密码到公钥体系。
          </p>
          <div className="mt-5 flex items-center gap-1 text-sm font-semibold" style={{ color: "var(--accent)" }}>
            进入单机实验
            <span className="transition group-hover:translate-x-1">→</span>
          </div>
        </Link>

        <Link
          href="/dual"
          className="group panel relative overflow-hidden p-8 transition hover:-translate-y-0.5"
        >
          <div className="font-mono text-xs tracking-[0.2em]" style={{ color: "var(--cyan)" }}>DUAL / SOCKET</div>
          <h2 className="mt-4 text-2xl font-bold">双机加解密</h2>
          <p className="mt-2 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
            两个进程通过 Socket 通信：DH 密钥协商 → 传输密码加密 → 解密端还原。后端调用 Python 实现，前端只做驱动与结果展示。
          </p>
          <div className="mt-5 flex items-center gap-1 text-sm font-semibold" style={{ color: "var(--cyan)" }}>
            进入双机加解密
            <span className="transition group-hover:translate-x-1">→</span>
          </div>
        </Link>
      </section>
    </div>
  );
}
