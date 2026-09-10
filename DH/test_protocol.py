#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""异常 TCP 协议测试：截断帧、非法帧、完整性错误、乱序和空闲超时。"""
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable
SERVER_TIMEOUT = 5


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(port):
    process = subprocess.Popen(
        [PY, "-u", "decrypt_server.py", "--port", str(port)],
        cwd=HERE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    line = process.stdout.readline()
    if not line.startswith("READY"):
        process.kill()
        process.wait()
        raise RuntimeError(line)
    return process


def finish_server(process, timeout=10):
    try:
        output = process.communicate(timeout=timeout)[0]
    except subprocess.TimeoutExpired:
        process.kill()
        output = process.communicate()[0]
        raise AssertionError(f"服务端未在预期时间退出: {output!r}")
    return output


def run_case(name, action, expected):
    port = free_port()
    server = start_server(port)
    try:
        action(port)
        output = finish_server(server)
        ok = server.returncode != 0 and expected in output
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            print(output)
            raise AssertionError(f"协议异常测试失败: {name}")
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()


def raw_frame(sock, payload):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def test_truncated_frame(port):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        payload = b'{"type":"dh_hello"}'
        sock.sendall(struct.pack("!I", len(payload) + 1) + payload)
        sock.shutdown(socket.SHUT_WR)


def test_invalid_json(port):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        raw_frame(sock, b"not-json")


def test_oversized_frame(port):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(struct.pack("!I", 1024 * 1024 + 1))


def test_invalid_dh_parameters(port):
    import dh_socket_common as common

    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        common.send_frame(sock, {"type": "dh_hello", "p": common.P,
                                 "g": common.G, "public": 1})


def test_bad_hmac(port):
    from dh_socket_common import (
        G, P, derive_material, encrypt_message, public_value,
        recv_frame, send_frame, shared_secret, transcript_hash,
    )

    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        alice_public = public_value(1234)
        send_frame(sock, {"type": "dh_hello", "p": P, "g": G,
                          "public": alice_public, "transport": "aes"})
        reply = recv_frame(sock)
        secret = shared_secret(reply["public"], 1234)
        tkey, mac_key = derive_material(secret, "aes")
        packet = encrypt_message("tampered", tkey, mac_key, "aes")
        packet["hmac"] = "0" * 64
        packet.update({"type": "encrypted_message",
                       "session": transcript_hash(alice_public, reply["public"]),
                       "seq": 0})
        send_frame(sock, packet)


def test_duplicate_sequence(port):
    from dh_socket_common import (
        G, P, public_value, recv_frame, send_frame,
    )

    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        alice_public = public_value(1234)
        send_frame(sock, {"type": "dh_hello", "p": P, "g": G,
                          "public": alice_public, "transport": "aes"})
        reply = recv_frame(sock)
        packet = {"type": "pubkey_request", "cipher": "rsa",
                  "session": reply["session"], "seq": 0}
        send_frame(sock, packet)
        recv_frame(sock)
        send_frame(sock, packet)


def test_idle_timeout():
    port = free_port()
    server = start_server(port)
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        started = time.monotonic()
        output = finish_server(server, timeout=SERVER_TIMEOUT + 3)
        elapsed = time.monotonic() - started
        ok = server.returncode != 0 and "timed out" in output and elapsed >= SERVER_TIMEOUT - 1
        print(f"[{'PASS' if ok else 'FAIL'}] 握手空闲超时")
        if not ok:
            print(output)
            raise AssertionError("握手空闲超时测试失败")
    finally:
        sock.close()
        if server.poll() is None:
            server.kill()
            server.wait()


def main():
    run_case("截断帧拒绝", test_truncated_frame, "连接在数据接收完成前关闭")
    run_case("非法 JSON 拒绝", test_invalid_json, "JSON")
    run_case("超大 JSON 帧拒绝", test_oversized_frame, "单帧数据超过安全上限")
    run_case("非法 DH 公开值拒绝", test_invalid_dh_parameters, "合法范围")
    run_case("错误 HMAC 拒绝", test_bad_hmac, "HMAC 校验失败")
    run_case("重复序号拒绝", test_duplicate_sequence, "重放/乱序")
    test_idle_timeout()
    print("PROTOCOL TEST PASS")


if __name__ == "__main__":
    main()
