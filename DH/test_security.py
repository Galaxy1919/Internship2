#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安全信道测试：认证 DH（防中间人）+ 重放保护。

覆盖：
  1. 错误 Bob 公钥 → Alice 验签失败（等价于中间人冒充 Bob 被识破）
  2. MITM 攻击 + Alice 无认证（--no-auth）→ 中间人解密成功
  3. MITM 攻击 + Alice 有认证（默认）→ Alice 检测到攻击并断开
  4. 重放保护：发送错误 seq 的帧 → 服务端拒绝
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

DH = Path(__file__).resolve().parent
PY = sys.executable


def _start(cmd, *args):
    # -u 关闭缓冲，确保 READY/就位 等标志能被及时读到
    return subprocess.Popen([PY, "-u", cmd, *args], cwd=DH,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _wait_ready(proc, marker, timeout=10):
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            buf += line
            if marker in line:
                return buf
    raise TimeoutError(f"等待 {marker!r} 超时，已读: {buf!r}")


def _drain(proc):
    try:
        return proc.stdout.read() or ""
    except Exception:
        return ""


def test_auth_wrong_pubkey():
    bob = _start("decrypt_server.py", "--port", "29091")
    ok = False
    try:
        _wait_ready(bob, "READY")
        r = subprocess.run([PY, "encrypt_client.py", "消息", "--port", "29091",
                            "--bob-pubkey", "1:2"], cwd=DH,
                           capture_output=True, text=True, timeout=30)
        if "检测到中间人" in (r.stdout + r.stderr):
            print("[PASS] auth 错误公钥被拒（= 中间人冒充 Bob 被识破）")
            ok = True
        else:
            print(f"[FAIL] auth 预期拒绝，实际 out={r.stdout!r} err={r.stderr!r}")
    finally:
        bob.kill()
    return ok


def test_mitm_noauth():
    bob = _start("decrypt_server.py", "--port", "29092")
    ok = False
    try:
        _wait_ready(bob, "READY")
        mitm = _start("mitm.py", "--mitm-port", "39002", "--target-port", "29092")
        try:
            _wait_ready(mitm, "就位")
            r = subprocess.run([PY, "encrypt_client.py", "绝密消息XYZ", "--port", "39002",
                                "--no-auth"], cwd=DH,
                               capture_output=True, text=True, timeout=30)
            mitm_out = _drain(mitm)
            if "绝密消息XYZ" in mitm_out:
                print("[PASS] MITM 无认证：中间人解密得到明文（攻击得逞）")
                ok = True
            else:
                print(f"[FAIL] MITM 无认证：中间人未解密成功，out={mitm_out!r}")
        finally:
            mitm.kill()
    finally:
        bob.kill()
    return ok


def test_mitm_auth():
    bob = _start("decrypt_server.py", "--port", "29093")
    ok = False
    try:
        _wait_ready(bob, "READY")
        mitm = _start("mitm.py", "--mitm-port", "39003", "--target-port", "29093")
        try:
            _wait_ready(mitm, "就位")
            r = subprocess.run([PY, "encrypt_client.py", "绝密消息XYZ", "--port", "39003"],
                               cwd=DH, capture_output=True, text=True, timeout=30)
            combined = r.stdout + r.stderr
            mitm_out = _drain(mitm)
            if "检测到中间人" in combined and "被识破" in mitm_out:
                print("[PASS] MITM 认证：Alice 检测到攻击并断开，中间人被识破")
                ok = True
            else:
                print(f"[FAIL] MITM 认证：alice={combined!r} mitm={mitm_out!r}")
        finally:
            mitm.kill()
    finally:
        bob.kill()
    return ok


def test_replay():
    from dh_socket_common import (
        P, G, public_value, shared_secret, derive_material,
        send_frame, recv_frame, encrypt_message, transcript_hash,
    )
    bob = _start("decrypt_server.py", "--port", "29094")
    ok = False
    try:
        _wait_ready(bob, "READY")
        s = socket.create_connection(("127.0.0.1", 29094), timeout=10)
        alice_public = public_value(1234)
        send_frame(s, {"type": "dh_hello", "p": P, "g": G, "public": alice_public,
                       "transport": "aes"})
        reply = recv_frame(s)
        bob_public = reply["public"]
        secret = shared_secret(bob_public, 1234)
        tkey, mac = derive_material(secret, "aes")
        session = transcript_hash(alice_public, bob_public)
        packet = encrypt_message("hello", tkey, mac, "aes")
        packet.update({"type": "encrypted_message", "session": session, "seq": 1})  # 错：应为 0
        send_frame(s, packet)
        s.close()
        time.sleep(0.3)
        out = _drain(bob)
        if "重放" in out or "seq" in out:
            print("[PASS] 重放保护：错误 seq 被服务端拒绝")
            ok = True
        else:
            print(f"[FAIL] 重放保护：服务端未拒绝，out={out!r}")
    finally:
        bob.kill()
    return ok


if __name__ == "__main__":
    tests = [test_auth_wrong_pubkey, test_mitm_noauth, test_mitm_auth, test_replay]
    results = []
    for test in tests:
        try:
            results.append(bool(test()))
        except Exception as exc:                      # 等待超时/端口占用等
            print(f"[FAIL] {test.__name__} 异常: {exc!r}")
            results.append(False)
    passed = all(results)
    print(f"\n安全信道测试: {'全部通过' if passed else '存在失败'} "
          f"({sum(results)}/{len(results)})")
    sys.exit(0 if passed else 1)
