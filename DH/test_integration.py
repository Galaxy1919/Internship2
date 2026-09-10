"""自动验收：启动解密端，再运行加密端，检查 DH、AES、HMAC 全链路（消息 + 文件）。"""
import socket
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECEIVED = HERE / "received"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port):
    server = subprocess.Popen([sys.executable, "decrypt_server.py", "--port", str(port)],
                              cwd=HERE, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    first = server.stdout.readline().strip()
    if not first.startswith("READY"):
        raise RuntimeError(first)
    return server


def test_message():
    port = free_port()
    server = start_server(port)
    client = subprocess.run([sys.executable, "encrypt_client.py",
                             "双机DH与AES联调通过", "--port", str(port)],
                            cwd=HERE, text=True, capture_output=True, timeout=10)
    rest = server.communicate(timeout=10)[0]
    print(client.stdout, end="")
    print(rest, end="")
    checks = [client.returncode == 0,
              "SERVER_ACK PASS" in client.stdout,
              "DH_SHARED 3836" in client.stdout,
              "DH_SHARED 3836" in rest,
              "PLAINTEXT 双机DH与AES联调通过" in rest]
    if not all(checks):
        print(client.stderr)
        raise SystemExit("INTEGRATION FAIL (message)")


def test_file():
    cases = [b"", b"A", b"B" * (64 * 1024 - 1), b"C" * (64 * 1024),
             b"D" * (64 * 1024 + 1)]
    for content in cases:
        port = free_port()
        server = start_server(port)
        with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as f:
            f.write(content)
            tmp = Path(f.name)
        saved_line = ""
        try:
            client = subprocess.run([sys.executable, "encrypt_client.py",
                                     "--file", str(tmp), "--port", str(port)],
                                    cwd=HERE, text=True, capture_output=True, timeout=30)
            rest = server.communicate(timeout=30)[0]
            print(client.stdout, end="")
            print(rest, end="")
            saved_line = next((line for line in rest.splitlines() if line.startswith("FILE_SAVED ")), "")
            saved = Path(saved_line.removeprefix("FILE_SAVED ")) if saved_line else None
            checks = [client.returncode == 0,
                      "SERVER_ACK PASS" in client.stdout,
                      f"FILE_SIZE {len(content)}" in client.stdout,
                      f"FILE_SIZE {len(content)}" in rest,
                      saved is not None and saved.exists() and saved.read_bytes() == content]
            if not all(checks):
                print(client.stderr)
                raise SystemExit(f"INTEGRATION FAIL (file size={len(content)})")
        finally:
            tmp.unlink(missing_ok=True)
            if saved_line:
                Path(saved_line.removeprefix("FILE_SAVED ")).unlink(missing_ok=True)


def test_file_rejects_size_mismatch():
    from dh_socket_common import send_file_chunks, send_frame
    from encrypt_client import connect_and_handshake

    port = free_port()
    server = start_server(port)
    sock = None
    try:
        sock, _, tkey, mac_key, session, transport = connect_and_handshake(
            "127.0.0.1", port)
        send_frame(sock, {"type": "file_meta", "filename": "../size-mismatch.bin",
                          "size": 1, "encrypted": True, "session": session, "seq": 0})
        send_file_chunks(sock, b"TOO LONG", tkey, mac_key, transport)
        sock.close()
        sock = None
        rest = server.communicate(timeout=10)[0]
        part_files = list(RECEIVED.glob(".part-*"))
        ok = (server.returncode != 0
              and "文件超过声明大小" in rest
              and "FILE_SAVED" not in rest
              and not part_files)
        print(f"[{'PASS' if ok else 'FAIL'}] file size mismatch rejected")
        if not ok:
            print(rest)
            raise SystemExit("INTEGRATION FAIL (file size mismatch)")
    finally:
        if sock is not None:
            sock.close()
        if server.poll() is None:
            server.kill()
        for part in RECEIVED.glob(".part-*"):
            part.unlink(missing_ok=True)


def test_cipher():
    for cid in ["aes", "des", "rc4", "ca", "vigenere", "playfair", "multiliteral", "transposition"]:
        port = free_port()
        server = start_server(port)
        client = subprocess.run([sys.executable, "encrypt_client.py",
                                 "--cipher", cid, "--text", "ATTACKATDAWN",
                                 "--port", str(port)],
                                cwd=HERE, text=True, capture_output=True, timeout=15)
        rest = server.communicate(timeout=15)[0]
        ok = (client.returncode == 0
              and "SERVER_ACK PASS" in client.stdout
              and "PLAINTEXT ATTACKATDAWN" in rest)
        print(f"[{'PASS' if ok else 'FAIL'}] {cid}")
        if not ok:
            print(client.stdout)
            print(client.stderr)
            print(rest)
            raise SystemExit(f"INTEGRATION FAIL (cipher: {cid})")


def test_pubkey():
    for cid in ["rsa", "elgamal", "sm2"]:
        port = free_port()
        server = start_server(port)
        client = subprocess.run([sys.executable, "encrypt_client.py",
                                 "--pubkey", cid, "--text", "PUBKEYTEST",
                                 "--port", str(port)],
                                cwd=HERE, text=True, capture_output=True, timeout=30)
        rest = server.communicate(timeout=30)[0]
        ok = (client.returncode == 0
              and "SERVER_ACK PASS" in client.stdout
              and "PLAINTEXT PUBKEYTEST" in rest)
        print(f"[{'PASS' if ok else 'FAIL'}] pubkey {cid}")
        if not ok:
            print(client.stdout)
            print(client.stderr)
            print(rest)
            raise SystemExit(f"INTEGRATION FAIL (pubkey: {cid})")


def test_digest():
    port = free_port()
    server = start_server(port)
    client = subprocess.run([sys.executable, "encrypt_client.py",
                             "--digest", "--text", "完整性校验测试",
                             "--port", str(port)],
                            cwd=HERE, text=True, capture_output=True, timeout=15)
    rest = server.communicate(timeout=15)[0]
    ok = (client.returncode == 0
          and "SERVER_ACK PASS" in client.stdout
          and "DIGEST_MATCH PASS" in rest)
    print(f"[{'PASS' if ok else 'FAIL'}] digest")
    if not ok:
        print(client.stdout)
        print(client.stderr)
        print(rest)
        raise SystemExit("INTEGRATION FAIL (digest)")


def test_ecdh():
    port = free_port()
    server = start_server(port)
    client = subprocess.run([sys.executable, "encrypt_client.py",
                             "--ecdh", "--port", str(port)],
                            cwd=HERE, text=True, capture_output=True, timeout=15)
    rest = server.communicate(timeout=15)[0]
    c = re.search(r"ECDH_SHARED (\w+)", client.stdout)
    s = re.search(r"ECDH_SHARED (\w+)", rest)
    ok = (client.returncode == 0 and c and s and c.group(1) == s.group(1))
    print(f"[{'PASS' if ok else 'FAIL'}] ecdh  (client={c.group(1) if c else None}, server={s.group(1) if s else None})")
    if not ok:
        print(client.stdout)
        print(client.stderr)
        print(rest)
        raise SystemExit("INTEGRATION FAIL (ecdh)")


def test_transport():
    for tr in ["des", "rc4", "ca"]:
        port = free_port()
        server = start_server(port)
        client = subprocess.run([sys.executable, "encrypt_client.py",
                                 "传输密码动态测试", "--transport", tr,
                                 "--port", str(port)],
                                cwd=HERE, text=True, capture_output=True, timeout=15)
        rest = server.communicate(timeout=15)[0]
        ok = (client.returncode == 0
              and "SERVER_ACK PASS" in client.stdout
              and f"TRANSPORT {tr}" in client.stdout
              and f"TRANSPORT {tr}" in rest
              and "PLAINTEXT 传输密码动态测试" in rest)
        print(f"[{'PASS' if ok else 'FAIL'}] transport {tr}")
        if not ok:
            print(client.stdout)
            print(client.stderr)
            print(rest)
            raise SystemExit(f"INTEGRATION FAIL (transport: {tr})")


def main():
    test_message()
    test_file()
    test_file_rejects_size_mismatch()
    test_cipher()
    test_pubkey()
    test_digest()
    test_ecdh()
    test_transport()
    print("INTEGRATION PASS")


if __name__ == "__main__":
    main()
