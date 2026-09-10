#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一验证 C 实现：编译、桥接层往返与 SM2 跨语言互操作。"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run_step(name: str, argv: list[str], cwd: Path) -> bool:
    print(f"$ {' '.join(argv)}  (cwd={cwd})")
    p = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=180)
    if p.stdout:
        print(p.stdout, end="")
    if p.stderr:
        print(p.stderr, end="")
    ok = p.returncode == 0
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n")
    return ok


def run_sm2_batch_check(sm2_dir: Path) -> bool:
    print(f"$ ./sm2_cli batch  (cwd={sm2_dir})")
    p = subprocess.Popen(["./sm2_cli", "batch"], cwd=sm2_dir, text=True,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert p.stdin is not None and p.stdout is not None
    p.stdin.write("keygen\n")
    p.stdin.flush()
    key_line = p.stdout.readline().strip()
    fields = key_line.split()
    ok = len(fields) == 4 and fields[0] == "ok"
    if ok:
        d, px, py = fields[1:]
        p.stdin.write(f"enc {px} {py} 48454c4c4f\n")
        p.stdin.flush()
        enc_line = p.stdout.readline().strip()
        enc_fields = enc_line.split()
        ok = len(enc_fields) == 2 and enc_fields[0] == "ok"
    if ok:
        p.stdin.write(f"dec {d} {enc_fields[1]}\n")
        p.stdin.flush()
        dec_line = p.stdout.readline().strip()
        ok = dec_line == "ok 48454c4c4f"
    p.stdin.write("quit\n")
    p.stdin.flush()
    bye = p.stdout.readline().strip()
    stderr = p.stderr.read()
    p.wait(timeout=10)
    if key_line:
        print(key_line)
    if 'enc_line' in locals():
        print(enc_line)
    if 'dec_line' in locals():
        print(dec_line)
    if bye:
        print(bye)
    if stderr:
        print(stderr, end="")
    ok = ok and p.returncode == 0 and bye == "ok bye"
    print(f"[{'PASS' if ok else 'FAIL'}] SM2 C batch 模式\n")
    return ok


def main() -> int:
    sm2_dir = ROOT / "publicKey" / "SM2"
    autokey_dir = ROOT / "ClassicalCiphers" / "PolyalphabeticSubstitution"
    trans_dir = ROOT / "ClassicalCiphers" / "Transposition"
    py = sys.executable

    steps = [
        ("SM2 C 编译", ["gcc", "-Wall", "-Wextra", "-std=gnu99", "-o", "sm2_cli",
                    "sm2_cli.c", "sm2.c", "sm3.c", "bn.c"], sm2_dir),
        ("SM2 C 点乘自检", ["./sm2_cli", "selftest"], sm2_dir),
        ("SM2 C/Python 互操作", [py, "interop.py", "--selftest"], sm2_dir),
        ("SM2 C 单进程基准", ["./sm2_cli", "bench", "5"], sm2_dir),
        ("Autokey C 编译", ["gcc", "-Wall", "-Wextra", "-std=gnu99", "-o", "autokey", "main.c"], autokey_dir),
        ("Autokey C 桥接层自检", [py, "autokey_c.py"], autokey_dir),
        ("双重置换 C 编译", ["gcc", "-Wall", "-Wextra", "-std=gnu99", "-o", "dt", "double_transposition.c"], trans_dir),
        ("双重置换 C 自检", ["./dt", "selftest"], trans_dir),
        ("双重置换 C 桥接层自检", [py, "double_transposition_c.py"], trans_dir),
    ]

    ok = True
    for name, argv, cwd in steps:
        ok = run_step(name, argv, cwd) and ok
        if name == "SM2 C 单进程基准":
            ok = run_sm2_batch_check(sm2_dir) and ok

    print("C VERIFY PASS" if ok else "C VERIFY FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
