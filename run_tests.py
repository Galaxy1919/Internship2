#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一运行项目验收测试，并输出可供桌面端解析的阶段标记。"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TESTS = [
    ("交叉验证", [sys.executable, "-u", "verify.py"], ROOT, 180),
    ("官方测试向量", [sys.executable, "-u", "test_vectors.py"], ROOT, 180),
    ("双机端到端", [sys.executable, "-u", "test_integration.py"], ROOT / "DH", 300),
    ("安全信道", [sys.executable, "-u", "test_security.py"], ROOT / "DH", 300),
    ("协议异常处理", [sys.executable, "-u", "test_protocol.py"], ROOT / "DH", 180),
    ("C 实现与互操作", [sys.executable, "-u", "c_verify.py"], ROOT, 600),
]


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    process.kill()


def run_test(index: int, total: int, name: str, argv: list[str], cwd: Path, timeout: int) -> bool:
    print(f"[START] {index}/{total} {name}", flush=True)
    print(f"$ {' '.join(argv)}  (cwd={cwd})", flush=True)
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        start_new_session=os.name == "posix",
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stop_process(process)
        output = (exc.output or "")
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        print(output, end="")
        elapsed = time.monotonic() - started
        print(f"[TIMEOUT] {name} elapsed={elapsed:.2f}s limit={timeout}s", flush=True)
        return False

    print(output, end="")
    elapsed = time.monotonic() - started
    ok = process.returncode == 0
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name} returncode={process.returncode} elapsed={elapsed:.2f}s", flush=True)
    return ok


def main() -> int:
    print(f"TEST_PLAN {len(TESTS)}", flush=True)
    passed = 0
    for index, (name, argv, cwd, timeout) in enumerate(TESTS, 1):
        if run_test(index, len(TESTS), name, argv, cwd, timeout):
            passed += 1
    failed = len(TESTS) - passed
    print(f"TEST_SUMMARY passed={passed} failed={failed} total={len(TESTS)}", flush=True)
    print("ALL_TESTS_PASS" if failed == 0 else "ALL_TESTS_FAIL", flush=True)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
