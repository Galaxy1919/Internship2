#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""双重置换（Double-Transposition）Python ↔ C 跨语言互操作与基准。

两套实现写的是同一件事（填矩阵 → 按密钥列序读出 → 再做一轮），但**矩阵填充约定不同**：

  Python 版（main.py）  ：变长列布局，不填任何伪字符。每列长度按明文长度算出
                          （如 5 字节 4 列 → 各列 2,1,1,1），因此中文/标点/二进制
                          都能无损恢复；密钥是**字母关键词**（如 "BCAD"），列序按字母序。
  C 版（double_transposition.c）：不足整行的末行用 'X' 补齐，两轮矩阵都是规整的
                          rows×n；密钥是**数字排列**（如 "3124"），列序按数字读，
                          密文自带 4 位十六进制明文长度前缀，解密时据此截掉 'X'。

因此互操作范围是「明文长度为密钥列数整数倍」的输入域：
  此时两轮都不会产生填充，两套实现的密文**逐字节相同**，可双向互解。
  非整数倍长度时，X 填充发生在第一轮的中间结果上并被第二轮的矩阵切分方式放大，
  Python 的变长布局无法还原，两者属于不同变体（不构成互操作），各自内部往返均正确。

用法：
  python3 interop.py --selftest    # 等价域对拍 + 双向互解 + 非等价域各自的往返
  python3 interop.py --bench       # 计时对比 C 与 Python

先编译 C 可执行文件（本目录下）：
  gcc -Wall -Wextra -std=gnu99 -o dt double_transposition.c
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
EXE = HERE / ("dt.exe" if sys.platform == "win32" else "dt")

COMPILE_HINT = ("未找到 C 可执行文件：\n"
                f"    {EXE}\n"
                "请先在本目录编译：\n"
                "    gcc -Wall -Wextra -std=gnu99 -o dt double_transposition.c")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


PY = _load("tr_main", HERE / "main.py")                       # 队友 Python 实现
BRIDGE = _load("dt_c", HERE / "double_transposition_c.py")    # 本目录 C 桥接层


# ---------------------------------------------------------------------------
# 密钥互转：数字排列（C） ↔ 字母关键词（Python）
# ---------------------------------------------------------------------------

def letter_key_from_perm(perm: str) -> str:
    """C 的数字排列密钥 → 等价的 Python 字母关键词。

    C 的 perm[i] 表示「第 i 个读出的列号」，而 Python 按字母序读列，
    所以让「读取次序」决定字母：读取得越早的列，关键词该位字母越小。
    """
    inv = [0] * (len(perm) + 1)
    for i, ch in enumerate(perm):
        inv[int(ch)] = i                       # inv[v] = 列 v 的读取次序
    return "".join(chr(ord("A") + inv[v]) for v in range(1, len(perm) + 1))


def perm_from_letter_key(key: str) -> str:
    """Python 字母关键词 → 等价的 C 数字排列密钥（上面映射的逆）。"""
    order = PY.column_order(key)
    perm = [0] * len(key)
    for pos, col in enumerate(order):
        perm[pos] = col + 1
    return "".join(str(x) for x in perm)


# ---------------------------------------------------------------------------
# C CLI 桥接
# ---------------------------------------------------------------------------

def _run(*args: str) -> str:
    p = subprocess.run([str(EXE), *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"C CLI 失败: {' '.join(args)}\n{p.stderr.strip()}")
    return p.stdout.rstrip("\r\n")


def c_encrypt(k1: str, k2: str, text: str) -> str:
    """返回 C 密文（不含长度前缀，已剥掉）。"""
    out = _run("enc", k1, k2, text)
    plen_hex, _, cipher = out.partition(":")
    assert int(plen_hex, 16) == len(text), f"C 返回的长度前缀不符: {out!r}"
    return cipher


def c_decrypt(k1: str, k2: str, cipher: str) -> str:
    """cipher 需为 C 的 "<4位hex明文长>:<密文>" 形式。"""
    return _run("dec", k1, k2, cipher)


# ---------------------------------------------------------------------------
# 跨语言往返验证
# ---------------------------------------------------------------------------

KEY_PAIRS = [("3124", "2413"), ("2413", "4321"), ("2143", "3124"),
             ("12", "21"), ("31245", "54321")]


def _text(n: int, rnd: random.Random) -> str:
    return "".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n))


def equivalent_domain() -> bool:
    """明文长度为列数整数倍：两套实现密文应逐字节相同，并可双向互解。"""
    ok, rnd = True, random.Random(20260910)
    print("等价域（明文长度为密钥列数整数倍，无填充）：")
    for perm1, perm2 in KEY_PAIRS:
        lk1, lk2 = letter_key_from_perm(perm1), letter_key_from_perm(perm2)
        width = len(perm1)
        for n in (width, width * 2, width * 3, width * 10):
            plain = _text(n, rnd)
            c_ct = c_encrypt(perm1, perm2, plain)
            py_ct = PY.encrypt(PY.encrypt(plain.encode(), lk1), lk2).decode()
            same = c_ct == py_ct
            py_back = PY.decrypt(PY.decrypt(c_ct.encode(), lk2), lk1).decode()
            c_back = c_decrypt(perm1, perm2, f"{len(py_ct):04x}:{py_ct}")
            good = same and py_back == plain and c_back == plain
            print(f"  [{'PASS' if good else 'FAIL'}] {perm1}/{perm2} -> {lk1}/{lk2}  "
                  f"len={n:3d}  密文一致={same}  Py解C={py_back == plain}  C解Py={c_back == plain}")
            ok = ok and good
    return ok


def non_equivalent_domain() -> bool:
    """非整数倍长度：两套实现不同变体，但各自内部往返必须正确。"""
    ok, rnd = True, random.Random(7)
    print("非整数倍长度（填充约定不同 → 不互操作，但各自自洽）：")
    perm1, perm2 = "3124", "2413"
    lk1, lk2 = letter_key_from_perm(perm1), letter_key_from_perm(perm2)
    for n in (1, 3, 5, 7, 11, 13):
        plain = _text(n, rnd)
        c_ct = c_encrypt(perm1, perm2, plain)
        py_ct = PY.encrypt(PY.encrypt(plain.encode(), lk1), lk2).decode()
        differ = c_ct != py_ct
        py_self = PY.decrypt(PY.decrypt(py_ct.encode(), lk2), lk1).decode() == plain
        c_self = c_decrypt(perm1, perm2, f"{n:04x}:{c_ct}") == plain
        bkey = BRIDGE.make_key(f"{perm1}|{perm2}")
        bridge_self = BRIDGE.decrypt(BRIDGE.encrypt(plain.encode(), bkey), bkey).decode() == plain
        good = differ and py_self and c_self and bridge_self
        print(f"  [{'PASS' if good else 'FAIL'}] len={n:3d}  密文不同(预期)={differ}  "
              f"Python往返={py_self}  C往返={c_self}  桥接层往返={bridge_self}")
        ok = ok and good
    return ok


def selftest() -> int:
    if not EXE.exists():
        print(COMPILE_HINT)
        return 2
    # 先自检密钥互转本身
    keys_ok = all(perm_from_letter_key(letter_key_from_perm(p)) == p
                  for p, _ in KEY_PAIRS)
    print(f"  [{'PASS' if keys_ok else 'FAIL'}] 密钥互转 数字排列 ↔ 字母关键词 双向自洽")
    print()
    ok = keys_ok and equivalent_domain()
    print()
    ok = non_equivalent_domain() and ok
    print("\n跨语言互操作通过" if ok else "\n跨语言互操作失败")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# 基准
# ---------------------------------------------------------------------------

def _bench(n_iter: int = 100) -> None:
    perm1, perm2 = "3124", "2413"
    lk1, lk2 = letter_key_from_perm(perm1), letter_key_from_perm(perm2)
    plain = "".join(chr(ord("A") + i % 26) for i in range(240))   # 240 是 4 的整数倍，落在等价域

    t0 = time.perf_counter()
    for _ in range(n_iter):
        c_decrypt(perm1, perm2, f"{len(plain):04x}:" + c_encrypt(perm1, perm2, plain))
    c_total = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(n_iter):
        PY.decrypt(PY.decrypt(PY.encrypt(PY.encrypt(plain.encode(), lk1), lk2), lk2), lk1)
    py_total = time.perf_counter() - t0

    print(f"C      {n_iter} 次加解密: {c_total * 1000:8.1f} ms  "
          f"({c_total / n_iter * 1000:6.2f} ms/次，含进程启动)")
    print(f"Python {n_iter} 次加解密: {py_total * 1000:8.1f} ms  "
          f"({py_total / n_iter * 1000:6.2f} ms/次，进程内直调)")


def bench() -> int:
    if not EXE.exists():
        print(COMPILE_HINT)
        return 2
    print("双重置换计时对比（C 经 subprocess 调用 vs Python 进程内直调）：")
    _bench(100)
    print("说明：置换只是 Python 的切片拼接（bytes 层由 CPython 的 C 实现完成），")
    print("      计算量本身很小；C 侧每次都要新建进程，所以这里快慢主要反映调用方式。")
    print("      C 实现的价值在于「跨语言密文一致」这一客观证据，而不是速度。")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="双重置换 Python↔C 跨语言互操作与基准")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", action="store_true")
    args = ap.parse_args()
    if args.bench:
        raise SystemExit(bench())
    raise SystemExit(selftest())
