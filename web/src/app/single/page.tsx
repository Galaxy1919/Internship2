import Link from "next/link";
import { LABS } from "@/lib/labs";

export default function Home() {
  return (
    <div>
      <section className="py-6 text-center">
        <div className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-xs" style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--accent)", boxShadow: "0 0 6px var(--accent)" }} />
          浏览器端纯 TypeScript 实现 · 交互式逐步演示
        </div>
        <h1 className="mx-auto mt-6 max-w-3xl text-4xl font-black leading-tight tracking-tight sm:text-5xl">
          密码学核心算法
          <br />
          <span style={{ background: "linear-gradient(90deg,#4ade80,#22d3ee,#a78bfa)", WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent" }}>
            交互实验演示
          </span>
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-base leading-relaxed" style={{ color: "var(--text-dim)" }}>
          从古典的纸笔密码到国密与现代公钥体系，十四个实验覆盖密码学演进的主线。
          每个演示都提供输入交互、过程可视化和逐步演算，帮助理解算法「为什么这样设计」。
        </p>
      </section>

      <section className="mt-10 grid gap-4 sm:grid-cols-2">
        {LABS.map((lab) => (
          <Link
            key={lab.href}
            href={lab.href}
            className="group panel relative overflow-hidden p-6 transition hover:-translate-y-0.5"
          >
            <div
              className="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full opacity-20 blur-2xl transition group-hover:opacity-40"
              style={{ background: lab.color }}
            />
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold tracking-widest" style={{ color: lab.color }}>
                {lab.no}
              </span>
              <span className="chip" style={{ borderColor: `${lab.color}44`, color: lab.color, background: `${lab.color}14` }}>
                {lab.tag}
              </span>
            </div>
            <h2 className="mt-4 text-xl font-bold">{lab.title}</h2>
            <div className="font-mono text-xs tracking-wide" style={{ color: "var(--text-faint)" }}>
              {lab.en}
            </div>
            <p className="mt-3 text-sm leading-relaxed" style={{ color: "var(--text-dim)" }}>
              {lab.desc}
            </p>
            <div className="mt-5 flex items-center gap-1 text-sm font-semibold" style={{ color: lab.color }}>
              进入实验
              <span className="transition group-hover:translate-x-1">→</span>
            </div>
          </Link>
        ))}
      </section>

      <section className="panel mt-10 grid gap-6 p-6 sm:grid-cols-3">
        {[
          ["🧩", "全部浏览器端计算", "不依赖任何后端服务，加密过程完全在本地可见、可审计"],
          ["📐", "过程逐步可视化", "方阵、矩阵、轮函数、交换记录全部展开为可交互的步骤"],
          ["🔬", "面向教学验证", "每个实验附带标准向量与对照说明，演示结果可手工验算"],
        ].map(([icon, title, desc]) => (
          <div key={title} className="flex gap-3">
            <div className="text-2xl">{icon}</div>
            <div>
              <div className="text-sm font-semibold">{title}</div>
              <div className="mt-1 text-xs leading-relaxed" style={{ color: "var(--text-dim)" }}>
                {desc}
              </div>
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}
