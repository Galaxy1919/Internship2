#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Playfair Cipher（多图替代密码 / 双字母组替代）
==============================================

原理
----
Playfair 是第一种“多图替代”（polygraphic）密码：不是一次换一个字母，而是
一次处理一个 *双字母组*（digraph），用 5×5 方阵上的几何规则替换，因此同一个
明文字母会因相邻字母不同而得到不同密文，显著削弱单字母频率分析。

构建 5×5 方阵
-------------
1. 先填密钥词（去重、I/J 合并），再补剩余字母，共 25 个（没有 J）。
2. 明文预处理：去掉非字母、大写、J→I，再两两分组；组内两个字母相同时
   在中间插入 X；最后若只剩单字母则补 X。

   以密钥 playfair example 构造的方阵：
       P L A Y F
       I R E X M
       B C D G H
       K N O Q S
       T U V W Z

加密规则（对每个双字母组 a-b）
-------------------------------
- 同行：a、b 各自右移一格（越界回卷）      row shift
- 同列：a、b 各自下移一格（越界回卷）      column shift
- 异行异列：交换列——a 取 b 的列、b 取 a 的列（构成矩形）  rectangle

创新点：可审计“分步轨迹”
------------------------
trace() 把方阵、明文双字母分组、每组命中的规则、替换前后坐标都展开打印，
每一步可手工验算，适合写进实验报告展示 Playfair 的几何替换过程。全部仅用
标准库实现。

经典已知向量（Wikipedia）
-------------------------
密钥 playfair example，明文 "Hide the gold in the tree stump"：
    密文 = BMODZBXDNABEKUDMUIXMMOUVIF

运行方式
--------
    python main.py                                # 交互模式
    python main.py -m encrypt -k PLAYFAIR -t "HIDE THE GOLD..."   # 加密
    python main.py -m decrypt -k PLAYFAIR -t "BMODZBXDN..."       # 解密
    python main.py --selftest                     # 已知向量自检
"""

import argparse
import sys
from pathlib import Path

ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # 25 个字母，I 与 J 合并到 I
SIZE = 5


# ---------------------------------------------------------------------------
# 方阵构造
# ---------------------------------------------------------------------------

def normalize_key(key: str) -> str:
    """密钥词规整为大写、去 J（J→I）、去重。"""
    seen = set()
    out = []
    for ch in key.upper():
        if not ch.isalpha():
            continue
        if ch == "J":
            ch = "I"
        if ch in seen:
            continue
        seen.add(ch)
        out.append(ch)
    return "".join(out)


def build_square(key: str = "") -> str:
    """按密钥词构造 25 字母方阵（行优先展开的一串字符串）。"""
    key = normalize_key(key)
    letters = list(key) + [ch for ch in ALPHABET if ch not in key]
    if len(letters) != 25:
        raise ValueError(f"方阵字母数异常: {len(letters)}（应为 25）")
    return "".join(letters)


def _pos(square: str, ch: str) -> tuple:
    """字母在方阵中的 (row, col)。"""
    idx = square.index(ch)
    return idx // SIZE, idx % SIZE


def _at(square: str, row: int, col: int) -> str:
    return square[row * SIZE + col]


def format_square(square: str) -> str:
    """打印 5×5 方阵。"""
    lines = ["     1  2  3  4  5", "  +----------------"]
    for r in range(SIZE):
        row = square[r * SIZE:(r + 1) * SIZE]
        lines.append(f"{r + 1} | " + "  ".join(row))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 明文预处理：双字母分组
# ---------------------------------------------------------------------------

def prepare_plaintext(text: str) -> str:
    """去非字母、大写、J→I；同字母对之间插 X；末尾单字母补 X。"""
    s = "".join("I" if ch.upper() == "J" else ch.upper()
                for ch in text if ch.isalpha())
    out = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else "X"
        if a == b:
            out.append(a)
            out.append("X")
            i += 1
        else:
            out.append(a)
            out.append(b)
            i += 2
    return "".join(out)


def digraphs(text: str) -> list:
    """把已预处理的文本切成双字母组列表。"""
    t = prepare_plaintext(text)
    return [t[i:i + 2] for i in range(0, len(t), 2)]


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def _encrypt_pair(square: str, a: str, b: str) -> str:
    """按 Playfair 规则加密一个双字母组。"""
    ra, ca = _pos(square, a)
    rb, cb = _pos(square, b)
    if ra == rb:                       # 同行：各自右移
        return _at(square, ra, (ca + 1) % SIZE) + _at(square, rb, (cb + 1) % SIZE)
    if ca == cb:                       # 同列：各自下移
        return _at(square, (ra + 1) % SIZE, ca) + _at(square, (rb + 1) % SIZE, cb)
    # 异行异列：交换列，构成矩形
    return _at(square, ra, cb) + _at(square, rb, ca)


def _decrypt_pair(square: str, a: str, b: str) -> str:
    """按 Playfair 规则解密一个双字母组（加密的逆操作）。"""
    ra, ca = _pos(square, a)
    rb, cb = _pos(square, b)
    if ra == rb:                       # 同行：各自左移
        return _at(square, ra, (ca - 1) % SIZE) + _at(square, rb, (cb - 1) % SIZE)
    if ca == cb:                       # 同列：各自上移
        return _at(square, (ra - 1) % SIZE, ca) + _at(square, (rb - 1) % SIZE, cb)
    return _at(square, ra, cb) + _at(square, rb, ca)


def encrypt(plain: str, key: str = "") -> str:
    """Playfair 加密。"""
    square = build_square(key)
    return "".join(_encrypt_pair(square, d[0], d[1]) for d in digraphs(plain))


def decrypt(cipher: str, key: str = "") -> str:
    """Playfair 解密。

    注意：解密只还原出预处理后的字符串（含为防重复字母插入的 X、末尾填充的
    X），无法自动区分哪个 X 是填充、哪个是真实字母，这是 Playfair 的固有限制。
    """
    square = build_square(key)
    c = "".join(ch for ch in cipher.upper() if ch.isalpha())
    if len(c) % 2 != 0:
        raise ValueError("密文字母个数不是偶数，无法按双字母组切分")
    return "".join(_decrypt_pair(square, c[i], c[i + 1]) for i in range(0, len(c), 2))


# ---------------------------------------------------------------------------
# 创新点：可审计分步轨迹
# ---------------------------------------------------------------------------

def trace(plain: str, key: str = "") -> dict:
    """展开每一步：双字母组、命中规则、替换前后坐标与结果。"""
    square = build_square(key)
    steps = []
    for d in digraphs(plain):
        a, b = d[0], d[1]
        ra, ca = _pos(square, a)
        rb, cb = _pos(square, b)
        if ra == rb:
            rule = "同行→右移"
        elif ca == cb:
            rule = "同列→下移"
        else:
            rule = "矩形→换列"
        c = _encrypt_pair(square, a, b)
        steps.append({
            "pair": d, "rule": rule,
            "a_pos": (ra + 1, ca + 1), "b_pos": (rb + 1, cb + 1),
            "out": c,
        })
    return {"square": square, "prepared": prepare_plaintext(plain),
            "ciphertext": encrypt(plain, key), "steps": steps}


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

def selftest() -> bool:
    ok = True

    def check(tag, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {tag}: {got}   期望 {want}")

    print("已知向量:")
    # Wikipedia 经典例
    check("加密  HIDE THE GOLD IN THE TREE STUMP",
          encrypt("Hide the gold in the tree stump", "playfair example"),
          "BMODZBXDNABEKUDMUIXMMOUVIF")

    # 解密回环：密文解回预处理后的明文（注意含填充 X）
    prepared = prepare_plaintext("Hide the gold in the tree stump")
    back = decrypt("BMODZBXDNABEKUDMUIXMMOUVIF", "playfair example")
    check("解密  BMODZBXDN... 还原为预处理文本", back, prepared)

    print("往返一致性:")
    samples = [
        ("", "ATTACK"),
        ("MONARCHY", "The quick brown fox jumps over the lazy dog"),
        ("PLAYFAIR", "Meet me at midnight"),
        ("SECRET", "HELLO WORLD"),
    ]
    for k, p in samples:
        c = encrypt(p, key=k)
        back = decrypt(c, key=k)
        norm = prepare_plaintext(p)
        good = back == norm
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] key={k or '(无)':10s} "
              f"{p:40s} -> {c}  还原={back}")

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive() -> None:
    print("=" * 50)
    print("Playfair Cipher（多图替代 / 双字母组）")
    print("=" * 50)
    key = input("输入密钥词(可留空): ").strip()
    square = build_square(key)
    print("当前方阵:")
    print(format_square(square))
    print("-" * 50)
    plain = input("输入明文: ").strip() or "Hide the gold in the tree stump"
    info = trace(plain, key)
    print("-" * 50)
    print(f"预处理明文 : {info['prepared']}")
    print(f"密文       : {info['ciphertext']}")
    print(f"解密还原   : {decrypt(info['ciphertext'], key)}")
    print("分步轨迹:")
    for i, s in enumerate(info["steps"], 1):
        print(f"  {i:2d}. {s['pair']}  ({s['rule']})  "
              f"{s['a_pos']}+{s['b_pos']} -> {s['out']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Playfair Cipher（多图替代密码）")
    parser.add_argument("-k", "--key", default="", help="密钥词（可选）")
    parser.add_argument("-t", "--text", help="要处理的文本（明文或密文）")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt"],
                        default="encrypt", help="加密还是解密（默认 encrypt）")
    parser.add_argument("--show-square", action="store_true", help="打印 5×5 方阵")
    parser.add_argument("--trace", action="store_true", help="打印分步替换轨迹")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    if args.show_square:
        print(format_square(build_square(args.key)))
        if args.text is None:
            return 0

    if args.text is not None:
        try:
            if args.mode == "encrypt":
                if args.trace:
                    info = trace(args.text, args.key)
                    print(f"预处理明文 : {info['prepared']}")
                    for i, s in enumerate(info["steps"], 1):
                        print(f"  {i:2d}. {s['pair']}  ({s['rule']})  "
                              f"{s['a_pos']}+{s['b_pos']} -> {s['out']}")
                    print(f"密文       : {info['ciphertext']}")
                else:
                    print(f"密文       : {encrypt(args.text, key=args.key)}")
            else:
                print(f"明文       : {decrypt(args.text, key=args.key)}")
        except ValueError as exc:
            print(f"错误: {exc}", file=sys.stderr)
            return 1
        return 0

    interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
