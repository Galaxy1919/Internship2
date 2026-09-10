#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Autokey（明文自密钥）C 实现桥接层 —— 把 C 可执行文件包装成框架统一接口。

对齐 DH/cipher_registry.py 4.1 节对称密码约定：
    encrypt(payload: bytes, key: bytes) -> bytes
    decrypt(cipher: bytes, key: bytes) -> bytes
    make_key(key_str=None) -> bytes

编译（在 main.c 所在目录执行）：
    gcc -Wall -Wextra -std=gnu99 -o autokey main.c

说明：
- 桥接采用 subprocess 调用 C 可执行文件的 enc/dec 子命令，不改队友 Python 实现。
- C 侧约定：仅对 A-Z 字母加解密，非字母原样保留且不消耗密钥流；密钥须为大写
  字母串（本层自动转大写）。明文/密文长度一致，无填充。
- 密文为 UTF-8 文本字节；明文里的非 A-Z 字符（空格/标点/中文）会原样出现在密文中。
- 与 Python 版（main.py 的 autokey-plaintext 变体）等价的范围：仅含大写字母的输入。
"""
import subprocess
import sys
from pathlib import Path

EXE = Path(__file__).resolve().parent / ("autokey.exe" if sys.platform == "win32" else "autokey")
DEFAULT_KEY = "QUEENLY"


def _run(args):
    try:
        r = subprocess.run([str(EXE), *args], capture_output=True, check=True)
    except FileNotFoundError:
        raise RuntimeError(
            f"未找到 C 可执行文件 {EXE}，请先编译："
            "gcc -Wall -Wextra -std=gnu99 -o autokey main.c") from None
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"autokey 调用失败: {err}") from None
    # 只去掉行尾换行：Windows 上 C 的 printf 输出行尾是 CR+LF，若只去 LF 会留下 CR，
    # 而 CR 属于「非字母」，会被 C 原样写进解密结果，导致往返不一致。
    return r.stdout.decode("utf-8").rstrip("\r\n")


def encrypt(payload: bytes, key: bytes) -> bytes:
    """加密：payload/key 均为 bytes，返回密文 bytes。"""
    text = payload.decode("utf-8")
    k = key.decode("utf-8").upper()
    return _run(["enc", k, text]).encode("utf-8")


def decrypt(cipher: bytes, key: bytes) -> bytes:
    """解密：返回明文 bytes。"""
    text = cipher.decode("utf-8")
    k = key.decode("utf-8").upper()
    return _run(["dec", k, text]).encode("utf-8")


def make_key(key_str=None) -> bytes:
    """无参返回默认关键词；有参时规范化为大写字母串的 UTF-8 字节。"""
    if key_str is None:
        return DEFAULT_KEY.encode("utf-8")
    if not isinstance(key_str, str):
        raise TypeError("Autokey 密钥应为字母字符串")
    return key_str.upper().encode("utf-8")


if __name__ == "__main__":
    # 独立自检：往返 + 与 test/test_autokey.c 相同的经典向量
    k = make_key("QUEENLY")
    for pt in (b"ATTACKATDAWN", b"HELLO WORLD", b"autokey cipher demo"):
        ct = encrypt(pt, k)
        assert decrypt(ct, k) == pt, f"往返失败: {pt!r}"
        print(f"OK  {pt!r} -> {ct!r}")
    print("autokey_c 桥接层自检通过")
