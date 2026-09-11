#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MD5 消息摘要算法实现
====================

原理
----
MD5把任意长度的消息压缩成128位的摘要,是一种单向散列函数。

算法分四步:

1. 填充
   先在消息末尾追加一个0x80字节(即比特1后跟7个0),然后填0,
   直到长度对64取模等于56。最后附上原始消息的位长度(64位小端),
   使总长度恰好是 64 字节的整数倍。

2. 初始化状态
   四个 32 位寄存器 A/B/C/D 取固定初值(小端):
      A=0x67452301  B=0xefcdab89  C=0x98badcfe  D=0x10325476

3. 分块压缩
   把消息切成 512 位(64 字节 = 16 个 32-bit 小端字)块,对每一块
   做 64 步运算,分成 4 轮,每轮用不同的非线性函数 F/G/H/I:

      Round 1 (0-15):  F(x,y,z) = (x & y) | (~x & z)
      Round 2 (16-31): G(x,y,z) = (x & z) | (y & ~z)
      Round 3 (32-47): H(x,y,z) = x ^ y ^ z
      Round 4 (48-63): I(x,y,z) = y ^ (x | ~z)

   每一步b' = b + left_rotate(a + Func(b,c,d) + M[k] + T[i], s)
   即a b c d = d b + left_rotate(a + Func(b,c,d) + M[k] + T[i], s) b c
   其中 T[i] = floor(2^32 * abs(sin(i+1))),s 为该步的循环左移量。
   一块处理完后,把 A/B/C/D 累加回全局状态。

4. 输出
   把最终的 A/B/C/D 按小端序拼成 16 字节,即摘要。

注意:MD5 已被证明存在实用的碰撞攻击(不同消息产生相同摘要),
早已不适合做数字签名、证书、密码存储。本实现仅作为教学演示,
用来核对文件完整性等非安全场景仍可见到,但不应用于任何安全用途。

运行方式
--------
    python main.py                       # 交互模式
    python main.py -t 文本                # 命令行模式
    python main.py --selftest            # RFC 1321 官方测试向量自检
"""

import argparse
import math
import struct
import sys


# ---------------------------------------------------------------------------
# 常量表
# ---------------------------------------------------------------------------

# 每一步的循环左移量 s(4 轮各 16 步,每轮的 4 个数循环使用)
S = (
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,   # Round 1
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,   # Round 2
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,   # Round 3
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,   # Round 4
)

# T[i] = floor(2^32 * abs(sin(i+1))),i = 0..63。取 sin 是为了拿到
# "看起来随机"的常数,消除结构性偏差。
T = tuple(int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64))

# 初始状态(小端字节序解读时依次是 01 23 45 67 89 ab cd ef ...)
A0, B0, C0, D0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

MASK32 = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def left_rotate(x: int, n: int) -> int:
    """32 位循环左移。"""
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def pad_message(message: bytes) -> bytes:
    """按 MD5 规则填充:0x80 + 若干 0x00 + 8 字节小端位长度。"""
    orig_len_bits = (len(message) * 8) & ((1 << 64) - 1) # 只取低64位（含3位长度校验位）
    msg = bytearray(message)
    msg.append(0x80)                          # 追加一个"1"比特
    while len(msg) % 64 != 56:                # 补 0 到 mod 64 == 56
        msg.append(0x00)
    msg += struct.pack("<Q", orig_len_bits)   # 8 字节小端位长度
    return bytes(msg)


def process_block(state: tuple, block: bytes) -> tuple:# 单块压缩
    """压缩一个 64 字节块,返回新的 (A, B, C, D)。"""
    a, b, c, d = state
    # 把块解成 16 个 32-bit 小端字
    M = struct.unpack("<16I", block)

    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (b & d) | (c & ~d)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7 * i) % 16

        f &= MASK32
        temp = (a + f + T[i] + M[g]) & MASK32
        # a <- d, d <- c, c <- b, b <- b + left_rotate(temp, S[i])
        a, d, c, b = d, c, b, (b + left_rotate(temp, S[i])) & MASK32

    return (# 手动截断，防止报错struct.pack 在值超过 32 位时会直接抛 struct.error。
        (state[0] + a) & MASK32,# 每一块只做这步一次，把当前的状态累加到初始的state[]里
        (state[1] + b) & MASK32,
        (state[2] + c) & MASK32,
        (state[3] + d) & MASK32,
    )


def md5(message: bytes) -> bytes:
    """计算 message 的 MD5 摘要,返回 16 字节。"""
    padded = pad_message(message)# 填充
    state = (A0, B0, C0, D0)
    for off in range(0, len(padded), 64):# 64字节为一块，每块执行单块压缩
        state = process_block(state, padded[off:off + 64])
    # 每个 32-bit 字按小端拼回,总共 16 字节
    return struct.pack("<4I", *state)


def md5_hex(message: bytes) -> str:
    """返回 32 位小写十六进制字符串,和常见工具输出一致。"""
    return md5(message).hex()


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

# RFC 1321 附录 A.5 的 7 组官方测试向量
RFC1321_VECTORS = [
    (b"",                                                                 "d41d8cd98f00b204e9800998ecf8427e"),
    (b"a",                                                                "0cc175b9c0f1b6a831c399e269772661"),
    (b"abc",                                                              "900150983cd24fb0d6963f7d28e17f72"),
    (b"message digest",                                                   "f96b697d7cb7938d525a2f31aaf161d0"),
    (b"abcdefghijklmnopqrstuvwxyz",                                       "c3fcd3d76192e4007dfb496cca67e13b"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",   "d174ab98d277d9f5a5611c2c9f419d9f"),
    (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                                                                          "57edf4a22be3c955ac49da2e2107b67a"),
]


def selftest() -> bool:
    """用 RFC 1321 官方向量核对每一步实现是否正确。"""
    print("RFC 1321 测试向量:")
    all_ok = True
    for msg, expected in RFC1321_VECTORS:
        actual = md5_hex(msg)
        ok = actual == expected
        all_ok = all_ok and ok
        preview = msg.decode("ascii") if len(msg) <= 20 else msg[:17].decode("ascii") + "..."
        print(f"  [{'PASS' if ok else 'FAIL'}] MD5({preview!r:24}) = {actual}")
        if not ok:
            print(f"         期望         = {expected}")

    # 顺带核对一次中文往返,确认 UTF-8 也能算
    zh = "MD5 测试 中文".encode("utf-8")
    zh_hex = md5_hex(zh)
    print(f"  中文 UTF-8 摘要: {zh_hex}")

    print("自检通过 ✓" if all_ok else "自检失败 ✗")
    return all_ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive() -> None:
    print("=" * 46)
    print("MD5 消息摘要")
    print("=" * 46)
    text = input("输入消息: ").strip()
    if text == "":
        print("(空消息)")
    data = text.encode("utf-8")
    digest = md5_hex(data)
    print("-" * 46)
    print(f"消息        : {text}")
    print(f"字节长度    : {len(data)}")
    print(f"MD5(hex)    : {digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description="MD5 消息摘要算法")
    parser.add_argument("-t", "--text", help="要计算摘要的文本(UTF-8)")
    parser.add_argument("--selftest", action="store_true", help="运行 RFC 1321 自检")
    args = parser.parse_args()

    if args.selftest:
        return 0 if selftest() else 1
    if args.text is not None:
        data = args.text.encode("utf-8")
        print(f"消息        : {args.text}")
        print(f"字节长度    : {len(data)}")
        print(f"MD5(hex)    : {md5_hex(data)}")
        return 0
    interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
