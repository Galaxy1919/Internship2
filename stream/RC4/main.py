#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC4
原理
RC4主要由两部分构成
1. KSA(密钥调度算法)
   用一个可变长度的密钥(1~256 字节)打乱一个 0~255 的初始S盒,
   得到初始状态。
2. PRGA(伪随机生成算法)
   从 S 盒中不断交换两个元素并输出一个字节,生成"密钥流"(keystream)。

运行
    python main.py                   # 交互模式
    python main.py -k 密钥 -t 明文    # 命令行模式
    python main.py --selftest        # 自检
"""

import argparse
import sys

def ksa(key: bytes) -> list:
    """KSA:密钥调度算法,把密钥打散成初始 S 盒。
    S 初始为 [0, 1, ..., 255],然后按密钥字节循环搅动。
    密钥长度 1~256 字节均可(为空则视为单字节 0)。
    """
    S = list(range(256))
    j = 0
    key_len = len(key) or 1
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) & 0xFF
        S[i], S[j] = S[j], S[i]      # 交换
    return S

def prga(S: list, n: int) -> bytes:
    """PRGA:伪随机生成算法,输出 n 字节密钥流。
    每次迭代:
      i 自增, j 累加 S[i],交换 S[i] 和 S[j],
      输出 S[(S[i] + S[j]) & 0xFF]。
    注意:这个函数会原地修改 S 盒,同一 S 只能调用一次。
    """
    keystream = bytearray()
    i = j = 0
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]# 交换使得S盒在prga过程中仍然会变化，增加随机性，否则生成的密钥流周期最大为256
        keystream.append(S[(S[i] + S[j]) & 0xFF]) # 将S[ S[i]+S[j] mod 256 ]的值作为轮密钥
    return bytes(keystream)

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """加密与解密是同一个操作:数据与密钥流逐字节异或。"""
    S = ksa(key)
    keystream = prga(S, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))

# 测试
def selftest() -> bool:
    """RFC 6229 测试向量。

    key = 0102030405060708090a0b0c0d0e0f10 时,
    密钥流前 16 字节(offset 0)必须是:
    9a c7 cc 9a 60 9d 1e f7 b2 93 28 99 cd e4 1b 97
    """
    key = bytes(range(1, 17))                       # 0x01..0x10, 16 字节
    expected = bytes.fromhex(
        "9ac7cc9a609d1ef7b2932899cde41b97"
    )
    S = ksa(key)
    actual = prga(S, 16)

    print("RFC 6229 测试向量:")
    print(f"期望密钥流: {expected.hex()}")
    print(f"实际密钥流: {actual.hex()}")
    ok = actual == expected

    # 加解密往返,确认一致性
    plain = "RC4 test 中文测试".encode("utf-8")
    cipher = rc4_crypt(plain, key)
    back = rc4_crypt(cipher, key)
    round_ok = back == plain
    print(f"加解密往返: {'PASS' if round_ok else 'FAIL'}")

    if ok and round_ok:
        print("自检通过")
        return True
    print("自检失败")
    return False

# 交互入口
def interactive() -> None:
    print("RC4 流密码")
    key_text = input("输入密钥: ").strip() or "default"
    plain_text = input("输入明文: ").strip() or "Attention is all you need"
    key = key_text.encode("utf-8")
    plain = plain_text.encode("utf-8")

    cipher = rc4_crypt(plain, key)
    back = rc4_crypt(cipher, key)

    print(f"密钥      : {key_text}")
    print(f"明文      : {plain_text}")
    print(f"密文(hex) : {cipher.hex().upper()}")
    print(f"解密还原  : {back.decode('utf-8')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="RC4")
    parser.add_argument("-k", "--key", help="密钥字符串")
    parser.add_argument("-t", "--text", help="明文/密文字符串")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.selftest:
        return 0 if selftest() else 1
    if args.key is not None and args.text is not None:
        key = args.key.encode("utf-8")
        data = args.text.encode("utf-8")
        cipher = rc4_crypt(data, key)
        back = rc4_crypt(cipher, key)
        print(f"密钥      : {args.key}")
        print(f"明文      : {args.text}")
        print(f"密文(hex) : {cipher.hex().upper()}")
        print(f"解密还原  : {back.decode('utf-8')}")
        return 0
    interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
