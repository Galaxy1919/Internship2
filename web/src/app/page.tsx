import Link from "next/link";

const LABS = [
  {
    href: "/polybius",
    no: "Lab 01",
    title: "Polybius 方阵密码",
    en: "Polybius Square",
    desc: "古典多字符替代密码：将 25 个字母排列成 5×5 方阵，每个字母用行列坐标 (1-5,1-5) 表示。支持带关键字的方阵构建与 I/J 合并规则。",
    tag: "单表替代",
    color: "#4ade80",
  },
  {
    href: "/transposition",
    no: "Lab 02",
    title: "列置换密码",
    en: "Columnar Transposition",
    desc: "换位密码的经典实现：明文按密钥宽度逐行写入矩阵，再按密钥字母排序后的列序读出密文。支持任意无重复字符密钥，密文保持字节级可逆。",
    tag: "换位密码",
    color: "#22d3ee",
  },
  {
    href: "/md5",
    no: "Lab 03",
    title: "MD5 消息摘要",
    en: "MD5 Message Digest",
    desc: "从零实现 RFC 1321 MD5：512-bit 分组、四轮非线性函数与循环移位，输出 128-bit 摘要。内置雪崩效应对比，直观展示输入微变导致摘要剧变。",
    tag: "哈希函数",
    color: "#a78bfa",
  },
  {
    href: "/dh",
    no: "Lab 04",
    title: "Diffie-Hellman 密钥交换",
    en: "Diffie–Hellman Key Exchange",
    desc: "公钥密码学奠基算法：Alice 与 Bob 基于离散对数难题在公开信道上协商共享密钥。支持小素数参数逐位演算、中间人篡改检测演示。",
    tag: "公钥密码",
    color: "#fbbf24",
  },
];

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
          从古典的纸笔密码到现代哈希与密钥交换，四个实验覆盖密码学演进的主线。
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
