#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CA(元胞自动机)流密码实现
=========================

原理
----
CA(Cellular Automata,元胞自动机)是一维格子,每个格子(细胞)只有 0/1
两种状态,按"规则"同步更新:新状态只取决于它自己和左右邻居的旧状态。

  ... [L] [C] [R] ...  ->  新 C' = f(L, C, R)

"规则编号"是把 8 种邻居组合(111,110,...,000)对应的输出拼成一个
8 位二进制数,再转十进制。例如 Rule 30:

  邻居 LCR: 111 110 101 100 011 010 001 000
  新状态 :   0   0   0   1   1   1   1   0     -> 二进制 00011110 = 30

Rule 30 有一个著名性质:由单个黑色细胞演化出的图案混沌、不可预测,
常被用作伪随机数发生器(Mathematica 的 RandomInteger 曾用它)。

作为流密码:
  1. 用密钥初始化一维细胞数组:先用 SHA-256 把密钥派生为 256 位
     种子(密码学里的密钥派生 KDF,让任意长度、哪怕只差一个字符的
     密钥都映射到完全不同的初始状态),再把种子比特填入细胞
  2. 先"预热"若干轮,让状态充分扩散,摆脱初始模式的简单性
  3. 之后每演化一轮,取整行细胞的比特拼成 8 字节,即密钥流
  4. 密文 = 明文 XOR 密钥流,解密同样再 XOR 一次

注意:本实现是教学演示。用 SHA-256 做密钥派生 + 预热 + 环形边界,
能缓解短密钥相关性与退化问题;真正用于生产仍需更严格的随机性
检验(如 NIST SP 800-22)。

运行方式
--------
    python main.py                       # 交互模式
    python main.py -k 密钥 -t 明文        # 命令行模式
    python main.py -k 密钥 -t 明文 --rule 110   # 换规则
    python main.py --selftest            # 往返/确定性自检
"""

import argparse
import hashlib
import sys

DEFAULT_CELLS = 64    # 细胞个数(每轮产出 64 / 8 = 8 字节密钥流)
DEFAULT_RULE = 30     # 默认演化规则
WARMUP_STEPS = 100    # 预热轮数,消除初始状态的相关性


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def build_rule_table(rule: int) -> list:
    """把规则编号展开成查表。

    rule 的 8 个二进制位,从高位到低位依次对应邻居组合
    111, 110, 101, ..., 000 的输出。
    """
    return [(rule >> (7 - i)) & 1 for i in range(8)]


def key_to_seed_cells(key: bytes, cells: int = DEFAULT_CELLS) -> list:
    """用密钥派生初始细胞状态。

    先用 SHA-256 把密钥打散成 256 位种子(等价于密码学里的密钥
    派生),再按位循环填充细胞。这样任意长度的密钥都能用,且密钥
    只差一个字符时初始状态也完全不同(雪崩效应)。不直接展开密钥
    比特的原因:短密钥循环填充会产生强相关的初始模式(比如密钥
    只有 8 字节时,64 个细胞全是同一段比特的重复)。
    """
    seed = hashlib.sha256(key).digest()# 字节串，sha256的32个字节相当于seed是32位的数组
    bits = []
    for b in seed:
        for shift in range(7, -1, -1):# 每个字节从高位到低位取
            bits.append((b >> shift) & 1)
    return [bits[i % len(bits)] for i in range(cells)]# bits共256位，而i只能到cell的64位，剩下的都丢弃了


def ca_step(cells: list, table: list) -> list:
    """演化一轮:每个细胞的新状态 = f(左邻居, 自己, 右邻居)。

    采用环形边界:最左细胞的左邻居是最右细胞,反之亦然,
    避免边界效应。
    """
    n = len(cells)
    new = [0] * n
    for i in range(n):
        left = cells[(i - 1) % n]
        center = cells[i]
        right = cells[(i + 1) % n]
        idx = (left << 2) | (center << 1) | right   # 即left center right拼接为三位二进制，对应邻居组合 -> 0..7
        new[i] = table[idx]
    return new


def ca_keystream(key: bytes,
                 n_bytes: int,
                 rule: int = DEFAULT_RULE,
                 cells: int = DEFAULT_CELLS,
                 warmup: int = WARMUP_STEPS) -> bytes:
    """由密钥生成 n_bytes 字节密钥流。

    流程:密钥 -> 初始细胞 -> 预热 -> 循环演化并拼字节 -> 截断到所需长度。
    """
    # 先演化一轮，遍历当前 64 个细胞，把每个 bit 左移拼进 byte_val；每拼满 8 个 bit，就追加一个字节到 keystream。
    table = build_rule_table(rule)
    state = key_to_seed_cells(key, cells)

    for _ in range(warmup):
        state = ca_step(state, table)

    keystream = bytearray()
    while len(keystream) < n_bytes:
        state = ca_step(state, table)
        byte_val = 0
        for i in range(cells):
            byte_val = (byte_val << 1) | state[i]
            if i % 8 == 7:
                keystream.append(byte_val)
                byte_val = 0
    return bytes(keystream[:n_bytes])


def ca_crypt(data: bytes, key: bytes, rule: int = DEFAULT_RULE) -> bytes:
    """加密与解密是同一个操作:数据与密钥流逐字节异或。"""
    # 明文⊕密钥流=密文，密文⊕密钥流=明文
    keystream = ca_keystream(key, len(data), rule=rule)
    return bytes(a ^ b for a, b in zip(data, keystream))


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

def selftest() -> bool:
    """自检三个性质:
    1. 加解密往返一致(解密能把密文还原成明文)
    2. 确定性:同一密钥两次生成同一密钥流
    3. 区分度:不同密钥生成的密钥流不同(随机性下限)
    """
    key1 = b"ca-demo-key"
    key2 = b"ca-demo-Key"          # 只差一个字母
    plain = "元胞自动机流密码测试 0123456789".encode("utf-8")

    cipher = ca_crypt(plain, key1)
    back = ca_crypt(cipher, key1)
    round_ok = back == plain

    ks1a = ca_keystream(key1, 64)
    ks1b = ca_keystream(key1, 64)
    deter_ok = ks1a == ks1b

    ks2 = ca_keystream(key2, 64)
    diff_ok = ks1a != ks2

    print("CA 流密码自检:")
    print(f"  加解密往返一致      : {'PASS' if round_ok else 'FAIL'}")
    print(f"  同密钥密钥流确定    : {'PASS' if deter_ok else 'FAIL'}")
    print(f"  不同密钥密钥流不同  : {'PASS' if diff_ok else 'FAIL'}")

    ok = round_ok and deter_ok and diff_ok
    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive(rule: int = DEFAULT_RULE) -> None:
    print("=" * 46)
    print(f"CA(元胞自动机)流密码  Rule {rule}")
    print("=" * 46)
    key_text = input("输入密钥: ").strip() or "default"
    plain_text = input("输入明文: ").strip() or "Hello CA"
    if not key_text:
        print("密钥不能为空!")
        return
    key = key_text.encode("utf-8")
    plain = plain_text.encode("utf-8")

    cipher = ca_crypt(plain, key, rule=rule)
    back = ca_crypt(cipher, key, rule=rule)

    print("-" * 46)
    print(f"密钥      : {key_text}")
    print(f"明文      : {plain_text}")
    print(f"密文(hex) : {cipher.hex().upper()}")
    print(f"解密还原  : {back.decode('utf-8')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="CA(元胞自动机)流密码")
    parser.add_argument("-k", "--key", help="密钥字符串")
    parser.add_argument("-t", "--text", help="明文/密文字符串")
    parser.add_argument("--rule", type=int, default=DEFAULT_RULE,
                        help=f"演化规则编号(默认 {DEFAULT_RULE},可选 30/90/110 等)")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.selftest:
        return 0 if selftest() else 1
    if args.key is not None and args.text is not None:
        if not args.key:
            print("密钥不能为空!")
            return 1
        key = args.key.encode("utf-8")
        data = args.text.encode("utf-8")
        cipher = ca_crypt(data, key, rule=args.rule)
        back = ca_crypt(cipher, key, rule=args.rule)
        print(f"密钥      : {args.key}")
        print(f"明文      : {args.text}")
        print(f"密文(hex) : {cipher.hex().upper()}")
        print(f"解密还原  : {back.decode('utf-8')}")
        return 0
    interactive(rule=args.rule)
    return 0


if __name__ == "__main__":
    sys.exit(main())
