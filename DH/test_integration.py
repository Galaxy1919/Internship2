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
    port = free_port()
    server = start_server(port)
    content = ("文件传输测试内容 1234567890 ABCDEFG。" * 500).encode("utf-8")
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f:
        f.write(content)
        tmp = Path(f.name)
    try:
        client = subprocess.run([sys.executable, "encrypt_client.py",
                                 "--file", str(tmp), "--port", str(port)],
                                cwd=HERE, text=True, capture_output=True, timeout=30)
        rest = server.communicate(timeout=30)[0]
        print(client.stdout, end="")
        print(rest, end="")
        saved = RECEIVED / tmp.name
        checks = [client.returncode == 0,
                  "SERVER_ACK PASS" in client.stdout,
                  "FILE " in client.stdout,
                  "FILE_SAVED " in rest,
                  saved.exists() and saved.read_bytes() == content]
        if not all(checks):
            print(client.stderr)
            raise SystemExit("INTEGRATION FAIL (file)")
    finally:
        tmp.unlink(missing_ok=True)
        (RECEIVED / tmp.name).unlink(missing_ok=True)


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


def main():
    test_message()
    test_file()
    test_cipher()
    test_pubkey()
    test_digest()
    test_ecdh()
    print("INTEGRATION PASS")


if __name__ == "__main__":
    main()
