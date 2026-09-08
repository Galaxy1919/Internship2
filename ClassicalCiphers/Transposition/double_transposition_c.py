#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""双重置换密码（Double-Transposition）C 实现桥接层。

对齐 DH/cipher_registry.py 4.1 节对称密码约定：
    encrypt(payload: bytes, key: bytes) -> bytes
    decrypt(cipher: bytes, key: bytes) -> bytes
    make_key(key_str=None) -> bytes

编译（在 double_transposition.c 所在目录执行）：
    gcc -Wall -Wextra -std=gnu99 -o dt double_transposition.c

密钥约定：双重置换需要两个列序密钥，统一打包成一个字符串 "K1|K2"（竖线分隔），
本层负责拆包。C 侧 enc 输出 "<4位hex明文长>:<密文>"，密文自携带长度前缀，
decrypt 时据此截掉 'X' 填充，因此密文字节本身就是可逆的完整载体。
明文长度 ≤ 4096，两个密钥列数必须相同。
"""
import subprocess
import sys
from pathlib import Path

EXE = Path(__file__).resolve().parent / ("dt.exe" if sys.platform == "win32" else "dt")
DEFAULT_KEY = "3124|4213"
KEY_SEP = "|"


def _run(args):
    try:
        r = subprocess.run([str(EXE), *args], capture_output=True, check=True)
    except FileNotFoundError:
        raise RuntimeError(
            f"未找到 C 可执行文件 {EXE}，请先编译："
            "gcc -Wall -Wextra -std=gnu99 -o dt double_transposition.c") from None
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"dt 调用失败: {err}") from None
    return r.stdout.decode("utf-8").rstrip("\n")


def _split_key(key: bytes):
    try:
        k1, k2 = key.decode("utf-8").split(KEY_SEP)
    except ValueError:
        raise ValueError(f"双重置换密钥格式应为 'K1{KEY_SEP}K2'，收到: {key!r}") from None
    return k1.strip(), k2.strip()


def encrypt(payload: bytes, key: bytes) -> bytes:
    """加密：返回 "<4位hex明文长>:<密文>" 文本的 UTF-8 字节（自含长度，可独立解密）。"""
    k1, k2 = _split_key(key)
    text = payload.decode("utf-8")
    return _run(["enc", k1, k2, text]).encode("utf-8")


def decrypt(cipher: bytes, key: bytes) -> bytes:
    """解密：cipher 为 encrypt 的输出字节，返回明文 bytes。"""
    k1, k2 = _split_key(key)
    enc = cipher.decode("utf-8")
    return _run(["dec", k1, k2, enc]).encode("utf-8")


def make_key(key_str=None) -> bytes:
    """无参返回默认双密钥；有参时接受 "K1|K2" 字符串。"""
    return (key_str or DEFAULT_KEY).encode("utf-8")


if __name__ == "__main__":
    # 独立自检：多种长度（含触发 X 填充的非整列倍数）往返
    k = make_key("3124|2143")
    for pt in (b"HELLO", b"DOUBLE TRANSPOSITION CIPHER", b"A"):
        ct = encrypt(pt, k)
        assert decrypt(ct, k) == pt, f"往返失败: {pt!r}"
        print(f"OK  {pt!r} -> {ct!r}")
    print("double_transposition_c 桥接层自检通过")
