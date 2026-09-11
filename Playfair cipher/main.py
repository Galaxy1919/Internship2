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
SIZE = 5                                 # 方阵边长


# ---------------------------------------------------------------------------
# 方阵构造
# ---------------------------------------------------------------------------

def normalize_key(key: str) -> str:
    """密钥词规整为大写、去 J（J→I）、去重。"""
    seen = set()                       # 已出现字母集合,用于去重
    out = []                           # 结果列表
    for ch in key.upper():             # 逐字符,统一转大写
        if not ch.isalpha():           # 跳过非字母
            continue
        if ch == "J":                  # J 合并进 I
            ch = "I"
        if ch in seen:                 # 重复字母只保留第一次
            continue
        seen.add(ch)                   # 标记已出现
        out.append(ch)                 # 首次出现才保留
    return "".join(out)                # 拼成字符串


def build_square(key: str = "") -> str:
    """按密钥词构造 25 字母方阵（行优先展开的一串字符串）。"""
    key = normalize_key(key)                              # 密钥规整
    letters = list(key) + [ch for ch in ALPHABET if ch not in key]  # 密钥字母在前,再补字母表剩余
    if len(letters) != 25:                                # 防御性检查
        raise ValueError(f"方阵字母数异常: {len(letters)}（应为 25）")
    return "".join(letters)                               # 返回 25 字符方阵


def _pos(square: str, ch: str) -> tuple:
    """字母在方阵中的 (row, col)。"""
    idx = square.index(ch)             # 字母在方阵字符串里的下标(0..24)
    return idx // SIZE, idx % SIZE     # 下标转 (行, 列)


def _at(square: str, row: int, col: int) -> str:
    return square[row * SIZE + col]    # 行优先:第 row 行第 col 列 = 下标 row*5+col


def format_square(square: str) -> str:
    """打印 5×5 方阵。"""
    lines = ["     1  2  3  4  5", "  +----------------"]  # 表头
    for r in range(SIZE):              # 逐行
        row = square[r * SIZE:(r + 1) * SIZE]  # 切出当前行
        lines.append(f"{r + 1} | " + "  ".join(row))  # 行号 + 内容
    return "\n".join(lines)            # 拼成多行字符串


# ---------------------------------------------------------------------------
# 明文预处理：双字母分组
# ---------------------------------------------------------------------------

def prepare_plaintext(text: str) -> str:
    """去非字母、大写、J→I；同字母对之间插 X；末尾单字母补 X。"""
    # 第一步:去掉非字母、转大写、J→I,得到纯字母串 s
    s = "".join("I" if ch.upper() == "J" else ch.upper()
                for ch in text if ch.isalpha())
    out = []                           # 预处理结果
    i = 0                              # 扫描游标
    while i < len(s):                  # 逐字符分组
        a = s[i]                       # 当前字母
        b = s[i + 1] if i + 1 < len(s) else "X"  # 下一个字母;末尾剩单字母则补 X
        if a == b:                     # 组内两个字母相同:中间插 X
            out.append(a)              # 保留 a
            out.append("X")            # 插入分隔用 X
            i += 1                     # 只前进 1,让第二个字母作为下一组开头
        else:                          # 不同:正常成组
            out.append(a)
            out.append(b)
            i += 2                     # 前进 2,消费这一组
    return "".join(out)                # 拼成预处理后的明文字符串


def digraphs(text: str) -> list:
    """把已预处理的文本切成双字母组列表。"""
    t = prepare_plaintext(text)        # 先预处理
    return [t[i:i + 2] for i in range(0, len(t), 2)]  # 每 2 个字母切一组


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def _encrypt_pair(square: str, a: str, b: str) -> str:
    """按 Playfair 规则加密一个双字母组。"""
    ra, ca = _pos(square, a)           # a 的坐标
    rb, cb = _pos(square, b)           # b 的坐标
    if ra == rb:                       # 同行：各自右移
        # 列 +1 右移,模 5 实现越界回卷(最右回到最左)
        return _at(square, ra, (ca + 1) % SIZE) + _at(square, rb, (cb + 1) % SIZE)
    if ca == cb:                       # 同列：各自下移
        # 行 +1 下移,模 5 越界回卷(最下回到最上)
        return _at(square, (ra + 1) % SIZE, ca) + _at(square, (rb + 1) % SIZE, cb)
    # 异行异列：交换列，构成矩形（a 取 b 的列，b 取 a 的列）
    return _at(square, ra, cb) + _at(square, rb, ca)


def _decrypt_pair(square: str, a: str, b: str) -> str:
    """按 Playfair 规则解密一个双字母组（加密的逆操作）。"""
    ra, ca = _pos(square, a)           # a 的坐标
    rb, cb = _pos(square, b)           # b 的坐标
    if ra == rb:                       # 同行：各自左移
        # 列 -1 左移,模 5 实现越界回卷(最左回到最右)
        return _at(square, ra, (ca - 1) % SIZE) + _at(square, rb, (cb - 1) % SIZE)
    if ca == cb:                       # 同列：各自上移
        # 行 -1 上移,模 5 越界回卷(最上回到最下)
        return _at(square, (ra - 1) % SIZE, ca) + _at(square, (rb - 1) % SIZE, cb)
    return _at(square, ra, cb) + _at(square, rb, ca)  # 矩形换列:与加密相同(自逆)


def encrypt(plain: str, key: str = "") -> str:
    """Playfair 加密。"""
    square = build_square(key)                       # 构造方阵
    # 每个双字母组套用加密规则,拼接成密文
    return "".join(_encrypt_pair(square, d[0], d[1]) for d in digraphs(plain))


def decrypt(cipher: str, key: str = "") -> str:
    """Playfair 解密。

    注意：解密只还原出预处理后的字符串（含为防重复字母插入的 X、末尾填充的
    X），无法自动区分哪个 X 是填充、哪个是真实字母，这是 Playfair 的固有限制。
    """
    square = build_square(key)                       # 构造方阵
    c = "".join(ch for ch in cipher.upper() if ch.isalpha())  # 密文清洗成大写字母串
    if len(c) % 2 != 0:                              # 密文字母数必须是偶数
        raise ValueError("密文字母个数不是偶数，无法按双字母组切分")
    # 每 2 个字母一组套用解密规则,拼接成明文
    return "".join(_decrypt_pair(square, c[i], c[i + 1]) for i in range(0, len(c), 2))


# ---------------------------------------------------------------------------
# 创新点：可审计分步轨迹
# ---------------------------------------------------------------------------

def trace(plain: str, key: str = "") -> dict:
    """展开每一步：双字母组、命中规则、替换前后坐标与结果。"""
    square = build_square(key)                       # 构造方阵
    steps = []                                       # 存放每一步的轨迹
    for d in digraphs(plain):                        # 遍历每个双字母组
        a, b = d[0], d[1]                            # 取出两个字母
        ra, ca = _pos(square, a)                     # a 坐标
        rb, cb = _pos(square, b)                     # b 坐标
        if ra == rb:                                 # 判断命中哪条规则
            rule = "同行→右移"
        elif ca == cb:
            rule = "同列→下移"
        else:
            rule = "矩形→换列"
        c = _encrypt_pair(square, a, b)              # 算出密文对
        steps.append({                               # 记录这一步的完整信息
            "pair": d, "rule": rule,
            "a_pos": (ra + 1, ca + 1), "b_pos": (rb + 1, cb + 1),  # 坐标转 1-based 便于阅读
            "out": c,
        })
    return {"square": square, "prepared": prepare_plaintext(plain),  # 返回方阵/预处理明文/密文/步骤
            "ciphertext": encrypt(plain, key), "steps": steps}


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

def selftest() -> bool:
    ok = True                                          # 总开关

    def check(tag, got, want):                         # 局部断言辅助
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
    prepared = prepare_plaintext("Hide the gold in the tree stump")  # 期望 = 预处理明文
    back = decrypt("BMODZBXDNABEKUDMUIXMMOUVIF", "playfair example")
    check("解密  BMODZBXDN... 还原为预处理文本", back, prepared)

    print("往返一致性:")
    samples = [                                        # 多组 (密钥,明文) 样例
        ("", "ATTACK"),
        ("MONARCHY", "The quick brown fox jumps over the lazy dog"),
        ("PLAYFAIR", "Meet me at midnight"),
        ("SECRET", "HELLO WORLD"),
    ]
    for k, p in samples:
        c = encrypt(p, key=k)                          # 加密
        back = decrypt(c, key=k)                       # 解密
        norm = prepare_plaintext(p)                    # 期望 = 预处理明文
        good = back == norm                            # 比较
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] key={k or '(无)':10s} "
              f"{p:40s} -> {c}  还原={back}")

    print("自检通过 ✓" if ok else "自检失败 ✗")         # 总体结果
    return ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive() -> None:
    print("=" * 50)                                    # 分隔线
    print("Playfair Cipher（多图替代 / 双字母组）")
    print("=" * 50)
    key = input("输入密钥词(可留空): ").strip()        # 读密钥词
    square = build_square(key)                         # 构造方阵
    print("当前方阵:")
    print(format_square(square))                       # 打印方阵
    print("-" * 50)
    plain = input("输入明文: ").strip() or "Hide the gold in the tree stump"  # 读明文,空输入用经典样例
    info = trace(plain, key)                           # 生成轨迹
    print("-" * 50)
    print(f"预处理明文 : {info['prepared']}")
    print(f"密文       : {info['ciphertext']}")
    print(f"解密还原   : {decrypt(info['ciphertext'], key)}")
    print("分步轨迹:")
    for i, s in enumerate(info["steps"], 1):           # 逐条打印替换步骤
        print(f"  {i:2d}. {s['pair']}  ({s['rule']})  "
              f"{s['a_pos']}+{s['b_pos']} -> {s['out']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Playfair Cipher（多图替代密码）")  # 命令行解析器
    parser.add_argument("-k", "--key", default="", help="密钥词（可选）")
    parser.add_argument("-t", "--text", help="要处理的文本（明文或密文）")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt"],
                        default="encrypt", help="加密还是解密（默认 encrypt）")
    parser.add_argument("--show-square", action="store_true", help="打印 5×5 方阵")
    parser.add_argument("--trace", action="store_true", help="打印分步替换轨迹")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()                         # 解析参数

    if args.selftest:                                  # 自检模式
        return 0 if selftest() else 1

    if args.show_square:                               # 只显示方阵
        print(format_square(build_square(args.key)))
        if args.text is None:                          # 没给文本就结束
            return 0

    if args.text is not None:                          # 命令行数据模式
        try:
            if args.mode == "encrypt":                 # 加密分支
                if args.trace:                         # 带 --trace 则打印分步轨迹
                    info = trace(args.text, args.key)
                    print(f"预处理明文 : {info['prepared']}")
                    for i, s in enumerate(info["steps"], 1):
                        print(f"  {i:2d}. {s['pair']}  ({s['rule']})  "
                              f"{s['a_pos']}+{s['b_pos']} -> {s['out']}")
                    print(f"密文       : {info['ciphertext']}")
                else:                                  # 不带 --trace 直接出密文
                    print(f"密文       : {encrypt(args.text, key=args.key)}")
            else:                                      # 解密分支
                print(f"明文       : {decrypt(args.text, key=args.key)}")
        except ValueError as exc:                      # 捕获非法输入
            print(f"错误: {exc}", file=sys.stderr)
            return 1
        return 0

    interactive()                                      # 无参数进入交互模式
    return 0


if __name__ == "__main__":
    sys.exit(main())                                   # 以 main() 返回值作为退出码
