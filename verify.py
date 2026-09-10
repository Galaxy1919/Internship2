#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""交叉验证脚本:把三份实现的输出与 Python 标准库 / 自身一致性对比。"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "MD5"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stream", "RC4"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stream", "CA"))

import importlib.util


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


md5_mod = load("md5_mod", os.path.join("MD5", "main.py"))
rc4_mod = load("rc4_mod", os.path.join("stream", "RC4", "main.py"))
ca_mod  = load("ca_mod",  os.path.join("stream", "CA",  "main.py"))

# 每节自检结果汇总，供退出码使用（桌面端「验证中心」据此判断整体是否通过）
section_results = []


# --------------------------------------------------------------------
# 1. MD5 vs hashlib(权威对比,覆盖各种长度和边界)
# --------------------------------------------------------------------
print("=" * 60)
print("1. MD5 vs Python hashlib(权威对比)")
print("=" * 60)

cases = [
    ("空字符串",  b""),
    ("abc",        b"abc"),
    ("55B(填充临界)",   b"a" * 55),
    ("56B(需多一块)",   b"a" * 56),
    ("64B(整块)",       b"a" * 64),
    ("1000B",           b"a" * 1000),
    ("随机 4KB",        os.urandom(4096)),
    ("中文 UTF-8",      "你好,世界。MD5 测试。".encode("utf-8")),
]

all_ok = True
for name, data in cases:
    mine = md5_mod.md5_hex(data)
    ref  = hashlib.md5(data).hexdigest()
    ok = mine == ref
    all_ok = all_ok and ok
    tag = "OK  " if ok else "FAIL"
    print(f"  [{tag}] {name:20s}  mine={mine}  hashlib={ref}")
print(f"MD5 交叉验证: {'全部通过 ✓' if all_ok else '存在差异 ✗'}")
section_results.append(all_ok)


# --------------------------------------------------------------------
# 2. RC4 加密 → 解密往返(多种长度)
# --------------------------------------------------------------------
print()
print("=" * 60)
print("2. RC4 加解密往返(多种长度)")
print("=" * 60)

key = b"test-key-2026"
all_ok = True
for size in [0, 1, 15, 16, 17, 100, 1024, 8192]:
    data = os.urandom(size)
    cipher = rc4_mod.rc4_crypt(data, key)
    back = rc4_mod.rc4_crypt(cipher, key)
    ok = back == data
    all_ok = all_ok and ok
    print(f"  [{'OK  ' if ok else 'FAIL'}] {size:>5} 字节  密文前16={cipher[:16].hex():<32}  往返={'一致' if ok else '不一致'}")
print(f"RC4 往返: {'全部通过 ✓' if all_ok else '存在失败 ✗'}")
section_results.append(all_ok)


# --------------------------------------------------------------------
# 3. CA 加解密往返 + 不同 rule
# --------------------------------------------------------------------
print()
print("=" * 60)
print("3. CA 加解密往返(测试多种 rule)")
print("=" * 60)

key = b"test-key-2026"
data = ("元胞自动机流密码,测试文本 1234567890 ABCDEFG。" * 3).encode("utf-8")
all_ok = True
for rule in [30, 90, 110, 45, 150]:
    cipher = ca_mod.ca_crypt(data, key, rule=rule)
    back = ca_mod.ca_crypt(cipher, key, rule=rule)
    ok = back == data
    all_ok = all_ok and ok
    print(f"  [{'OK  ' if ok else 'FAIL'}] rule={rule:>3}  密文前16={cipher[:16].hex():<32}  往返={'一致' if ok else '不一致'}")
print(f"CA 往返: {'全部通过 ✓' if all_ok else '存在失败 ✗'}")
section_results.append(all_ok)


# --------------------------------------------------------------------
# 4. 雪崩效应:密钥/明文只差 1 位,输出应有约一半比特不同
# --------------------------------------------------------------------
print()
print("=" * 60)
print("4. 雪崩效应观察(理想值:MD5 约 50% 比特翻转)")
print("=" * 60)

def bit_diff_ratio(a: bytes, b: bytes) -> float:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b)) / (len(a) * 8)

m1 = b"The quick brown fox jumps over the lazy dog"
m2 = b"The quick brown fox jumps over the lazy dOg"    # 只差一个大小写
h1 = md5_mod.md5(m1)
h2 = md5_mod.md5(m2)
print(f"  MD5 差 1 字符 -> 比特翻转率 = {bit_diff_ratio(h1, h2):.1%}")

k1 = b"key-A"
k2 = b"key-B"
c1 = rc4_mod.rc4_crypt(b"\x00" * 64, k1)
c2 = rc4_mod.rc4_crypt(b"\x00" * 64, k2)
print(f"  RC4 换密钥后密钥流比特翻转率 = {bit_diff_ratio(c1, c2):.1%}")

c1 = ca_mod.ca_crypt(b"\x00" * 64, k1)
c2 = ca_mod.ca_crypt(b"\x00" * 64, k2)
print(f"  CA  换密钥后密钥流比特翻转率 = {bit_diff_ratio(c1, c2):.1%}")

print()
passed = all(section_results)
print(f"交叉验证汇总: {'全部通过' if passed else '存在失败'} "
      f"({sum(section_results)}/{len(section_results)} 节通过)")
sys.exit(0 if passed else 1)
