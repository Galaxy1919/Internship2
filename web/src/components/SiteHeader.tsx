"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LABS } from "@/lib/labs";

export default function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  const isHome = pathname === "/";
  const isDual = pathname.startsWith("/dual");
  const isSingleRoot = pathname === "/single";
  // 其余是单个 lab 页（/aes、/rsa …）

  return (
    <header
      className="sticky top-0 z-40 border-b backdrop-blur-xl"
      style={{ borderColor: "var(--border)", background: "rgba(7,9,15,0.8)" }}
    >
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-2.5 font-mono text-sm font-bold tracking-tight">
          <span
            className="flex h-7 w-7 items-center justify-center rounded-md font-bold text-black"
            style={{
              background: "linear-gradient(135deg,#4ade80,#22d3ee)",
              boxShadow: "0 0 16px rgba(74,222,128,.4)",
            }}
          >
            Σ
          </span>
          <span>
            密码学实验演示
            <span className="ml-2 hidden text-xs font-normal sm:inline" style={{ color: "var(--text-faint)" }}>
              Internship2 · Web
            </span>
          </span>
        </Link>

        <nav className="flex items-center gap-1">
          {isHome ? null : isDual ? (
            <>
              <Link href="/single" className="navlink whitespace-nowrap px-3 py-1.5 text-sm">
                单机实验
              </Link>
              <span className="whitespace-nowrap px-3 py-1.5 text-sm font-semibold" style={{ color: "var(--cyan)" }}>
                双机加解密
              </span>
            </>
          ) : (
            <>
              {isSingleRoot ? (
                <span className="whitespace-nowrap px-3 py-1.5 text-sm font-semibold" style={{ color: "var(--accent)" }}>
                  单机实验
                </span>
              ) : (
                <div className="relative" ref={ref}>
                  <button
                    onClick={() => setOpen((v) => !v)}
                    className="navlink flex items-center gap-1 whitespace-nowrap px-3 py-1.5 text-sm font-semibold"
                    style={{ color: "var(--accent)" }}
                  >
                    单机实验
                    <span className="text-[10px]" style={{ color: "var(--text-faint)" }}>
                      ▾
                    </span>
                  </button>
                  {open && (
                    <div
                      className="absolute right-0 top-full z-50 mt-1 w-72 max-h-[60vh] overflow-auto rounded-lg border p-1 shadow-2xl"
                      style={{ borderColor: "var(--border)", background: "rgba(10,13,22,0.97)" }}
                    >
                      {LABS.map((lab) => {
                        const active = pathname === lab.href;
                        return (
                          <Link
                            key={lab.href}
                            href={lab.href}
                            className="flex items-center justify-between gap-2 rounded-md px-3 py-1.5 text-sm transition hover:bg-white/5"
                            style={active ? { background: "rgba(74,222,128,0.1)" } : undefined}
                          >
                            <span>
                              <span className="mr-2 font-mono text-xs" style={{ color: lab.color }}>
                                {lab.no.replace("Lab ", "")}
                              </span>
                              <span style={{ color: active ? "var(--text)" : "var(--text-dim)" }}>{lab.title}</span>
                            </span>
                            {active && (
                              <span className="text-xs" style={{ color: "var(--accent)" }}>
                                ●
                              </span>
                            )}
                          </Link>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
              <Link href="/dual" className="navlink whitespace-nowrap px-3 py-1.5 text-sm">
                双机加解密
              </Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}
