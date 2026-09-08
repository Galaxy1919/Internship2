import type { Metadata } from "next";
import "./globals.css";
import SiteHeader from "@/components/SiteHeader";

export const metadata: Metadata = {
  title: "密码学实验演示 · Internship2",
  description: "古典密码 · 哈希 · 密钥交换 —— 密码学课程实验交互演示",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body className="min-h-screen antialiased">
        <SiteHeader />
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
        <footer
          className="mx-auto max-w-6xl px-4 pb-10 pt-4 text-center text-xs"
          style={{ color: "var(--text-faint)" }}
        >
          密码学原理课程实验演示 · 单机实验浏览器端实现 / 双机加解密 Python 后端
        </footer>
      </body>
    </html>
  );
}
