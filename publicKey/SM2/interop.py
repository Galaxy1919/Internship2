#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SM2 Python ↔ C 跨语言互操作与基准。

Python 版（main.py）与 C 版（sm2.c + sm2_cli）是同一算法（sm2p256v1）的两套独立
实现，数学上一致，但密文序列化不同：

  Python 密文：04 || x1(32) || y1(32) || C3(32) || C2(明文长)   （C1 带 04 前缀，C3 在 C2 前）
  C     密文：      x1(32) || y1(32) || C2(明文长) || C3(32)     （C1 无前缀，C2 在 C3 前）

本模块提供两套格式互转 + 调 C CLI 的桥接函数，并做跨语言往返验证与基准。
基准会区分 C 单进程循环与 Python 反复启动 C CLI 的总耗时，避免把 subprocess
启动和十六进制 I/O 成本误算成 C 算法本体耗时；sm2_cli 另有 batch 模式，供
后续以常驻子进程方式减少重复启动成本。

用法：
  python3 interop.py --selftest    # 跨语言往返验证（C 加密→Py 解密；Py 加密→C 解密）
  python3 interop.py --bench       # 基准对比 C vs Python
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DH_ROOT = ROOT / "DH"

if str(DH_ROOT) not in sys.path:
    sys.path.insert(0, str(DH_ROOT))

from cipher_registry import SM2 as PySM2  # noqa: E402

CLI = HERE / "sm2_cli"


# ---------------------------------------------------------------------------
# 密文格式互转
# ---------------------------------------------------------------------------

def py_to_c(ct_py: bytes) -> bytes:
    """Python 密文(04||x||y||C3||C2) → C 密文(x||y||C2||C3)。"""
    if ct_py[0] != 0x04:
        raise ValueError("Python 密文应以 04 开头")
    return ct_py[1:65] + ct_py[97:] + ct_py[65:97]


def c_to_py(ct_c: bytes) -> bytes:
    """C 密文(x||y||C2||C3) → Python 密文(04||x||y||C3||C2)。"""
    return b"\x04" + ct_c[:64] + ct_c[-32:] + ct_c[64:-32]


# ---------------------------------------------------------------------------
# C CLI 桥接
# ---------------------------------------------------------------------------

def _run(*args) -> str:
    p = subprocess.run([str(CLI), *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"C CLI 失败: {' '.join(args)}\n{p.stderr}")
    return p.stdout.strip()


def c_keygen():
    """调 C keygen，返回 (d_hex, px_hex, py_hex)，均为 64 位小写 hex。"""
    d = px = py = None
    for line in _run("keygen").splitlines():
        if line.startswith("d "):
            d = line[2:]
        elif line.startswith("Px "):
            px = line[3:]
        elif line.startswith("Py "):
            py = line[3:]
    return d, px, py


def c_encrypt(px_hex, py_hex, plaintext: bytes) -> bytes:
    return bytes.fromhex(_run("enc", px_hex, py_hex, plaintext.hex()))


def c_decrypt(d_hex, c_ct: bytes) -> bytes:
    return bytes.fromhex(_run("dec", d_hex, c_ct.hex()))


def c_bench(n_iter=20):
    fields = {}
    for line in _run("bench", str(n_iter)).splitlines():
        key, _, value = line.partition(" ")
        fields[key] = value.strip()
    try:
        return float(fields["total_ms"]) / 1000.0, float(fields["per_round_ms"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"C bench 输出格式异常: {fields!r}") from exc


# ---------------------------------------------------------------------------
# 跨语言往返验证
# ---------------------------------------------------------------------------

def cross_language_roundtrip(plaintext: bytes) -> bool:
    ok = True

    # 方向 A：C 加密 → Python 解密
    d_hex, px, py = c_keygen()
    c_ct = c_encrypt(px, py, plaintext)
    rec_a = PySM2.decrypt_pke(c_to_py(c_ct), int(d_hex, 16))
    good_a = rec_a == plaintext
    print(f"  [{'PASS' if good_a else 'FAIL'}] C 加密 → Python 解密: {rec_a.decode('utf-8', errors='replace')!r}")
    ok = ok and good_a

    # 方向 B：Python 加密 → C 解密
    d_int, pub = PySM2.generate_keypair()
    py_ct = PySM2.encrypt_pke(plaintext, pub)
    rec_b = c_decrypt(f"{d_int:064x}", py_to_c(py_ct))
    good_b = rec_b == plaintext
    print(f"  [{'PASS' if good_b else 'FAIL'}] Python 加密 → C 解密: {rec_b.decode('utf-8', errors='replace')!r}")
    ok = ok and good_b

    return ok


def selftest() -> int:
    plain = "SM2 跨语言互操作 测试消息 2026".encode("utf-8")
    print("跨语言往返验证：")
    good = cross_language_roundtrip(plain)
    print("跨语言互操作通过 ✓" if good else "跨语言互操作失败 ✗")
    return 0 if good else 1


# ---------------------------------------------------------------------------
# 基准对比（C vs Python）
# ---------------------------------------------------------------------------

def _bench(n_iter=20):
    plaintext = "benchmark message 1234567890".encode("utf-8")

    # C 单进程基准：C 进程内部循环，排除 Python subprocess 启动成本
    c_inner_total, c_inner_per_ms = c_bench(n_iter)

    # C CLI 总耗时：每次 enc/dec 都经 subprocess，体现当前桥接层真实调用成本
    d_hex, px, py = c_keygen()
    t0 = time.perf_counter()
    for _ in range(n_iter):
        c_decrypt(d_hex, c_encrypt(px, py, plaintext))
    c_cli_total = time.perf_counter() - t0

    # Python 基准：同一进程内调用 Python 实现；其大整数运算底层由 CPython C 代码完成
    d_int, pub = PySM2.generate_keypair()
    t0 = time.perf_counter()
    for _ in range(n_iter):
        PySM2.decrypt_pke(PySM2.encrypt_pke(plaintext, pub), d_int)
    py_total = time.perf_counter() - t0

    print(f"C 单进程循环      {n_iter} 次加解密: {c_inner_total*1000:8.1f} ms  ({c_inner_per_ms:.2f} ms/次)")
    print(f"C CLI 子进程路径  {n_iter} 次加解密: {c_cli_total*1000:8.1f} ms  ({c_cli_total/n_iter*1000:.2f} ms/次)")
    print(f"Python 进程内调用 {n_iter} 次加解密: {py_total*1000:8.1f} ms  ({py_total/n_iter*1000:.2f} ms/次)")
    print("说明: C CLI 子进程路径包含进程启动、hex 转换和管道 I/O；C 单进程循环更接近算法本体耗时。")
    return c_inner_total, c_cli_total, py_total


def bench() -> int:
    print("SM2 加解密基准（区分 C 本体循环与 CLI 调用成本）：")
    _bench(20)
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SM2 Python↔C 跨语言互操作与基准")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", action="store_true")
    args = ap.parse_args()
    if args.bench:
        raise SystemExit(bench())
    raise SystemExit(selftest())
