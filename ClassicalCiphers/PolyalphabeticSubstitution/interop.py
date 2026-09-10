#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Autokey Python ↔ C 跨语言互操作与基准。

Python 版（main.py 的 autokey-plaintext 变体）与 C 版（main.c + autokey 可执行文件）
是同一算法（Vigenère 1586 年原始设计：密钥流 = 密钥词 + 明文本身）的两套独立实现：

    加密 C[i] = (P[i] + K[i]) mod 26 ，解密逐位串行推进（密钥尾部取自已解出的明文）

两套实现的等价范围：**仅含大写字母的输入**。
  - Python 版先用 letters_only() 丢弃非字母字符；
  - C 版保留非字母字符、且不消耗密钥流（如 "HELLO WORLD" → "XYPPB HMYPO"）。
所以非字母输入是「两种约定」，不属于互操作范围；本脚本只在大写字母输入域上对拍。

用法：
  python3 interop.py --selftest    # 跨语言往返验证（C 加密→Py 解密；Py 加密→C 解密）
  python3 interop.py --bench       # 计时对比 C 与 Python

先编译 C 可执行文件（本目录下）：
  gcc -Wall -Wextra -std=gnu99 -o autokey main.c
"""
from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXE = HERE / ("autokey.exe" if sys.platform == "win32" else "autokey")

COMPILE_HINT = ("未找到 C 可执行文件：\n"
                f"    {EXE}\n"
                "请先在本目录编译：\n"
                "    gcc -Wall -Wextra -std=gnu99 -o autokey main.c")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


PY = _load("pa_main", HERE / "main.py")                       # 队友 Python 实现
BRIDGE = _load("autokey_c", HERE / "autokey_c.py")            # 本目录 C 桥接层


# ---------------------------------------------------------------------------
# C CLI 桥接（直调，用于和桥接层交叉印证）
# ---------------------------------------------------------------------------

def _run(*args: str) -> str:
    p = subprocess.run([str(EXE), *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"C CLI 失败: {' '.join(args)}\n{p.stderr.strip()}")
    return p.stdout.rstrip("\r\n")


def c_encrypt(key: str, text: str) -> str:
    return _run("enc", key, text)


def c_decrypt(key: str, text: str) -> str:
    return _run("dec", key, text)


# ---------------------------------------------------------------------------
# 跨语言往返验证
# ---------------------------------------------------------------------------

CASES = [("QUEENLY", "ATTACKATDAWN"), ("KEY", "ATTACK"), ("LEMON", "A"),
         ("CRYPT", "HELLOWORLD"), ("SECRET", "INFORMATIONSECURITY")]


def cross_language_roundtrip() -> bool:
    ok = True
    for key, text in CASES:
        c_ct = c_encrypt(key, text)
        py_ct = PY.autokey_plaintext_encrypt(text, key)
        same = c_ct == py_ct
        py_back = PY.autokey_plaintext_decrypt(c_ct, key)
        c_back = c_decrypt(key, py_ct)
        print(f"  [{'PASS' if same else 'FAIL'}] 密文一致  {key:7s} {text:20s} -> {c_ct}")
        if not same:
            print(f"         C={c_ct!r}  Python={py_ct!r}")
        print(f"  [{'PASS' if py_back == text else 'FAIL'}] C 加密 → Python 解密: {py_back!r}")
        print(f"  [{'PASS' if c_back == text else 'FAIL'}] Python 加密 → C 解密: {c_back!r}")
        ok = ok and same and py_back == text and c_back == text

    # 随机长文本（只含大写字母，落在等价输入域内）
    rnd = random.Random(20260910)
    for n in (2, 13, 64, 200, 512):
        text = "".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n))
        key = "AUTOKEY"
        good = c_encrypt(key, text) == PY.autokey_plaintext_encrypt(text, key)
        print(f"  [{'PASS' if good else 'FAIL'}] 随机 {n:3d} 字母密文一致")
        ok = ok and good

    # 桥接层（autokey_c.py）应与直调 CLI 结果一致，且自身往返正确
    key_b = BRIDGE.make_key("QUEENLY")
    for payload in (b"ATTACKATDAWN", b"HELLO WORLD"):
        ct = BRIDGE.encrypt(payload, key_b)
        good = (ct.decode() == c_encrypt("QUEENLY", payload.decode())
                and BRIDGE.decrypt(ct, key_b) == payload)
        print(f"  [{'PASS' if good else 'FAIL'}] 桥接层一致且往返: {payload!r}")
        ok = ok and good
    return ok


def selftest() -> int:
    if not EXE.exists():
        print(COMPILE_HINT)
        return 2
    print("Autokey 跨语言往返验证（等价输入域：仅大写字母）：")
    good = cross_language_roundtrip()
    print("跨语言互操作通过" if good else "跨语言互操作失败")
    return 0 if good else 1


# ---------------------------------------------------------------------------
# 基准（诚实说明：古典密码算不动 CPU，这里量的是调用开销）
# ---------------------------------------------------------------------------

def _bench(n_iter: int = 100) -> None:
    key, text = "QUEENLY", ("ATTACKATDAWN" * 30)[:300]

    t0 = time.perf_counter()
    for _ in range(n_iter):
        c_decrypt(key, c_encrypt(key, text))
    c_total = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(n_iter):
        PY.autokey_plaintext_decrypt(PY.autokey_plaintext_encrypt(text, key), key)
    py_total = time.perf_counter() - t0

    print(f"C      {n_iter} 次加解密: {c_total * 1000:8.1f} ms  "
          f"({c_total / n_iter * 1000:6.2f} ms/次，含进程启动)")
    print(f"Python {n_iter} 次加解密: {py_total * 1000:8.1f} ms  "
          f"({py_total / n_iter * 1000:6.2f} ms/次，进程内直调)")


def bench() -> int:
    if not EXE.exists():
        print(COMPILE_HINT)
        return 2
    print("Autokey 计时对比（C 经 subprocess 调用 vs Python 进程内直调）：")
    _bench(100)
    print("说明：多表替代是 O(n) 查表运算，本身几乎不耗 CPU；C 侧每次都要新建进程，")
    print("      所以这里快慢主要反映调用方式，而不是算法速度。C 实现的价值在于")
    print("      「跨语言密文一致」这一客观证据，而不是把古典密码跑得更快。")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Autokey Python↔C 跨语言互操作与基准")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", action="store_true")
    args = ap.parse_args()
    if args.bench:
        raise SystemExit(bench())
    raise SystemExit(selftest())
