#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multiliteral Cipher(多字符替换密码 / Polybius Square 版本)
=============================================================

原理
----
"单表替换"(Monoalphabetic Substitution)是指整篇密文都用同一张替换
表,每个明文字母对应唯一的密文符号。

"Multiliteral"(多字符)则强调:一个明文字母被替换成 *多个* 密文字符
组成的组合。最经典的代表是 **Polybius Square(波利比奥斯方阵)**,
公元前 2 世纪的希腊史学家 Polybius 提出:把 25 个字母排进 5×5 网格,
每个字母用它所在的 (行号, 列号) 表示,一个字母 -> 两个数字。

    标准 5×5 方阵(I 与 J 合并到同一格):

          1  2  3  4  5
        +---------------
      1 | A  B  C  D  E
      2 | F  G  H  I  K       (I/J 合并)
      3 | L  M  N  O  P
      4 | Q  R  S  T  U
      5 | V  W  X  Y  Z

    示例: H -> (2,3) -> "23"
          HELLO -> 23 15 31 31 34

带关键字的变体(Keyed Polybius)
--------------------------------
可以先把一个"密钥词"填进方阵,重复字母只保留首次出现,然后再补上
剩余字母,这样得到一张打乱的方阵。这一步等价于对 25 个字母做一个
单表替换,把方阵位置当作密文,共同构成"Multiliteral 单表替换"。

    以密钥词 KEYWORD 为例:
    去重后 = K, E, Y, W, O, R, D
    追加剩余字母(跳过已出现的,I/J 合并):
      K E Y W O
      R D A B C
      F G H I L
      M N P Q S
      T U V X Z

    此时 H -> (3,3) -> "33",A -> (2,3) -> "23"

加密与解密
----------
- 加密:把明文里的字母查表 -> 两个数字组成的坐标,非字母字符按需
  处理(默认丢弃,以便解密时能干净地按 2 位一组切分)。J 视作 I。
- 解密:把密文按 2 位一组切开,反查方阵 -> 字母。

注意:Polybius square 是单表替换,受频率分析攻击。密钥词只能提供
非常有限的强度提升,仅作为课程教学演示。

运行方式
--------
    python main.py                                      # 交互模式
    python main.py -m encrypt -k KEYWORD -t HELLO       # 命令行加密
    python main.py -m decrypt -k KEYWORD -t "33 15 ..." # 命令行解密
    python main.py --selftest                           # 官方向量自检
"""

import argparse
import sys


# 5×5 网格用的字母表:I 与 J 合并到 I(经典约定,让 25 个字母正好放下)
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"    # 注意:没有 J
SIZE = 5                                  # 方阵边长(行数=列数=5)


# ---------------------------------------------------------------------------
# 方阵构造
# ---------------------------------------------------------------------------

def normalize_key(key: str) -> str:
    """把密钥词规整成一串大写、去重、去 J 的字母序列。"""
    seen = set()          # 记录已经出现过的字母,用于去重
    out = []              # 保存规整后字母序列的列表
    for ch in key.upper():  # 统一转大写,让大小写不影响结果
        if not ch.isalpha():  # 跳过空格、标点、数字等非字母字符
            continue
        if ch == "J":                # J -> I,和主字母表约定一致
            ch = "I"
        if ch in seen:               # 重复字母:只保留第一次出现
            continue
        seen.add(ch)                 # 标记该字母已出现
        out.append(ch)               # 首次出现的字母才进结果
    return "".join(out)              # 列表拼成字符串返回


def build_square(key: str = "") -> str:
    """根据密钥词构造 5×5 方阵。

    返回一个长 25 的字符串,按行优先展开。key 为空则退化成标准方阵
    ABCDE / FGHIK / LMNOP / QRSTU / VWXYZ。
    """
    key = normalize_key(key)         # 先把密钥词规整(大写/去重/去J)
    letters = list(key)              # 方阵开头先放密钥字母
    for ch in ALPHABET:              # 再按字母表顺序补齐剩余字母
        if ch not in key:            # 只补密钥里没出现过的字母
            letters.append(ch)
    if len(letters) != 25:           # 防御性检查:方阵必须正好 25 个字母
        raise ValueError(f"方阵字母数异常:{len(letters)}(应为 25)")
    return "".join(letters)          # 返回行优先展开的 25 字符方阵


def build_tables(square: str):
    """由方阵字符串构造正向/反向查表,返回 (encode, decode)。

    encode: {字母 -> "行列"}    如 {'H': '23'}
    decode: {"行列" -> 字母}    如 {'23': 'H'}
    """
    encode = {}                      # 正向表:字母 -> 坐标字符串
    decode = {}                      # 反向表:坐标字符串 -> 字母
    for idx, ch in enumerate(square):  # 遍历方阵每个位置(0..24)
        row = idx // SIZE + 1        # 行号:idx//5 得 0..4,加 1 变 1..5
        col = idx % SIZE + 1         # 列号:idx%5 得 0..4,加 1 变 1..5
        code = f"{row}{col}"         # 坐标拼成两位字符串,如 "23"
        encode[ch] = code            # 正向映射:字母 -> "23"
        decode[code] = ch            # 反向映射:"23" -> 字母
    return encode, decode            # 两张表一起返回


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def encrypt(plain: str, key: str = "", sep: str = " ") -> str:
    """加密:字母 -> 两位数字坐标。非字母字符丢弃。

    参数 sep 只影响输出美观(默认空格分隔每对数字),不影响解密结果
    (解密会先剥离所有非数字字符再按 2 位一组切)。
    """
    encode, _ = build_tables(build_square(key))  # 构造方阵并取正向查表(丢弃反向表)
    out = []                         # 存放每个字母对应的坐标
    for ch in plain.upper():         # 明文统一转大写后逐字符处理
        if ch == "J":                # J 视作 I,与方阵约定一致
            ch = "I"
        if ch in encode:             # 是方阵里的字母就查表
            out.append(encode[ch])
        # 其它字符(空格、标点、数字)一律丢弃
    return sep.join(out)             # 用分隔符(默认空格)把坐标连成密文


def decrypt(cipher: str, key: str = "") -> str:
    """解密:把密文里的数字按 2 位一组切开,查表反向恢复字母。"""
    _, decode = build_tables(build_square(key))  # 构造方阵并取反向查表(丢弃正向表)
    digits = "".join(ch for ch in cipher if ch.isdigit())  # 先剥掉空格/冒号等,只留数字
    if len(digits) % 2 != 0:         # 数字个数必须是偶数,才能两两成组
        raise ValueError("密文数字个数不是偶数,无法按 2 位一组切分")
    out = []                         # 存放恢复出的字母
    for i in range(0, len(digits), 2):  # 每 2 位一组推进
        pair = digits[i:i + 2]       # 取出当前这一组坐标
        if pair not in decode:       # 坐标非法(如含 0 或 6-9)则报错
            raise ValueError(f"非法坐标 {pair}(每一位应在 1-5)")
        out.append(decode[pair])     # 反向查表得到字母
    return "".join(out)              # 拼成明文字符串


def format_square(square: str) -> str:
    """把 25 字母方阵打印成好看的 5×5 网格。"""
    lines = ["    1  2  3  4  5", "  +---------------"]  # 表头:列号 + 分隔线
    for r in range(SIZE):            # 逐行
        row = square[r * SIZE:(r + 1) * SIZE]  # 切出当前这一行的 5 个字母
        lines.append(f"{r + 1} | " + "  ".join(row))  # 行号 + 行内容
    return "\n".join(lines)          # 拼成多行字符串


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

def selftest() -> bool:
    """三组已知向量:
    1. 标准方阵(无密钥)对 HELLO,应得 23 15 31 31 34。
    2. 标准方阵下 J 视作 I,JAM = IAM = 24 11 32。
    3. 关键字方阵 KEYWORD 下 ATTACK,期望值直接手算得出。
    另外验证若干轮明文的加密-解密往返一致。
    """
    ok = True                         # 总开关:任何一条失败都会置 False

    # 1. 标准方阵 HELLO
    c1 = encrypt("HELLO")             # 无密钥 -> 用标准方阵
    expect1 = "23 15 31 31 34"        # 手算期望值
    ok1 = c1 == expect1               # 对比实际与期望
    print(f"  [{'PASS' if ok1 else 'FAIL'}] 标准方阵 HELLO -> {c1}   期望 {expect1}")
    ok = ok and ok1                   # 汇总进总开关

    # 2. J -> I 合并
    c2 = encrypt("JAM")               # JAM 应等价于 IAM
    expect2 = "24 11 32"              # I=24, A=11, M=32
    ok2 = c2 == expect2
    print(f"  [{'PASS' if ok2 else 'FAIL'}] J/I 合并 JAM   -> {c2}   期望 {expect2}")
    ok = ok and ok2

    # 3. 关键字 KEYWORD 下 ATTACK
    #    方阵首行 KEYWO,第二行 RDABC,...
    #    A=(2,3)=23  T=(5,1)=51  C=(2,5)=25  K=(1,1)=11
    #    ATTACK = 23 51 51 23 25 11
    c3 = encrypt("ATTACK", key="KEYWORD")  # 带密钥词 -> 用打乱方阵
    expect3 = "23 51 51 23 25 11"     # 手算期望值
    ok3 = c3 == expect3
    print(f"  [{'PASS' if ok3 else 'FAIL'}] key=KEYWORD ATTACK -> {c3}   期望 {expect3}")
    ok = ok and ok3

    # 4. 往返一致
    samples = [                       # (密钥, 明文) 测试样例
        ("", "ATTACK AT DAWN"),
        ("", "The quick brown fox"),
        ("POLYBIUS", "Meet me at midnight"),
        ("KEYWORD", "HELLO WORLD"),
    ]
    for k, p in samples:
        c = encrypt(p, key=k)         # 先加密
        back = decrypt(c, key=k)      # 再解密
        # 期望还原成:大写、去掉非字母、J->I 之后的字符串
        norm = "".join(("I" if ch == "J" else ch) for ch in p.upper() if ch.isalpha())
        ok_round = back == norm       # 比较解密结果与规范化明文
        ok = ok and ok_round
        print(f"  [{'PASS' if ok_round else 'FAIL'}] 往返 key={k!r:<10} {p!r:30} -> {c}  还原={back}")

    print("自检通过 ✓" if ok else "自检失败 ✗")  # 打印总体结果
    return ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive() -> None:
    print("=" * 50)                    # 打印分隔线
    print("Multiliteral Cipher (Polybius Square 5×5)")
    print("=" * 50)
    key = input("输入密钥词(可留空): ").strip()  # 读密钥词,去掉首尾空白
    square = build_square(key)         # 构造方阵
    print("当前方阵:")
    print(format_square(square))       # 打印方阵供核对
    print("-" * 50)

    plain = input("输入明文: ").strip() or "HELLO POLYBIUS"  # 读明文,空输入用默认样例
    cipher = encrypt(plain, key=key)   # 加密
    back = decrypt(cipher, key=key)    # 解密回环

    print("-" * 50)
    print(f"密钥词    : {key or '(无,使用标准 A-Z)'}")  # 打印密钥(空则提示标准方阵)
    print(f"明文      : {plain}")
    print(f"密文      : {cipher}")
    print(f"解密还原  : {back}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Multiliteral Cipher(单表替换 / Polybius Square 5×5)")  # 命令行解析器
    parser.add_argument("-k", "--key", default="", help="密钥词(可选,默认标准方阵)")
    parser.add_argument("-t", "--text", help="要处理的文本(明文或密文)")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt"],
                        default="encrypt", help="加密还是解密(默认 encrypt)")
    parser.add_argument("--sep", default=" ",
                        help="加密输出坐标之间的分隔符(默认空格)")
    parser.add_argument("--show-square", action="store_true",
                        help="打印当前使用的 5×5 方阵")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()         # 解析命令行参数

    if args.selftest:                  # 自检模式:跑 selftest 并按结果返回退出码
        return 0 if selftest() else 1

    if args.show_square:               # 只显示方阵
        print(format_square(build_square(args.key)))
        if args.text is None:          # 没给文本:打印完方阵就结束
            return 0

    if args.text is not None:          # 命令行数据模式:处理 -t 传入的文本
        try:
            if args.mode == "encrypt":  # 按模式选择加密或解密
                result = encrypt(args.text, key=args.key, sep=args.sep)
            else:
                result = decrypt(args.text, key=args.key)
        except ValueError as exc:       # 捕获非法输入(如坐标越界)
            print(f"错误:{exc}", file=sys.stderr)
            return 1
        print(f"密钥词    : {args.key or '(无)'}")
        print(f"模式      : {args.mode}")
        print(f"输入      : {args.text}")
        print(f"输出      : {result}")
        return 0

    interactive()                      # 无参数则进入交互模式
    return 0


if __name__ == "__main__":
    sys.exit(main())                   # 以 main() 返回值作为进程退出码
