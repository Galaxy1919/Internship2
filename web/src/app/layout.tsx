import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "密码学实验演示 · Internship2",
  description: "古典密码 · 哈希 · 密钥交换 —— 密码学课程实验交互演示",
};

const NAV = [
  { href: "/", label: "总览", exact: true },
  { href: "/polybius", label: "Polybius 方阵" },
  { href: "/transposition", label: "列置换" },
  { href: "/md5", label: "MD5" },
  { href: "/dh", label: "Diffie-Hellman" },
];

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body className="min-h-screen antialiased">
        <header className="sticky top-0 z-40 border-b backdrop-blur-xl" style={{ borderColor: "var(--border)", background: "rgba(7,9,15,0.8)" }}>
          <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
            <Link href="/" className="flex items-center gap-2.5 font-mono text-sm font-bold tracking-tight">
              <span className="flex h-7 w-7 items-center justify-center rounded-md font-bold text-black" style={{ background: "linear-gradient(135deg,#4ade80,#22d3ee)", boxShadow: "0 0 16px rgba(74,222,128,.4)" }}>
                Σ
              </span>
              <span>
                密码学实验演示
                <span className="ml-2 hidden text-xs font-normal sm:inline" style={{ color: "var(--text-faint)" }}>Internship2 · Web</span>
              </span>
            </Link>
            <nav className="flex items-center gap-1 overflow-x-auto">
              {NAV.map((n) => (
                <Link
                  key={n.href}
                  href={n.href}
                  className="navlink whitespace-nowrap px-3 py-1.5 text-sm"
                >
                  {n.label}
                </Link>
              ))}
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
        <footer className="mx-auto max-w-6xl px-4 pb-10 pt-4 text-center text-xs" style={{ color: "var(--text-faint)" }}>
          密码学原理课程实验演示 · 所有算法均为浏览器端从零实现
        </footer>
      </body>
    </html>
  );
}
