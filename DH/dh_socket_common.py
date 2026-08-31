"""DH-TCP 实验公共模块：参数、快速模幂、密钥派生和长度帧协议。"""
import hashlib
import hmac
import json
import struct
from pathlib import Path
import sys

# 复用本项目手写 AES，而不是调用密码库。
AES_DIR = Path(__file__).resolve().parents[1] / "Block" / "AES"
sys.path.insert(0, str(AES_DIR))
import main as aes  # noqa: E402

P = 7919
G = 5

def fast_pow(base, exponent, modulus):
    result = 1
    base %= modulus
    while exponent:
        if exponent & 1:
            result = result * base % modulus
        base = base * base % modulus
        exponent >>= 1
    return result

def public_value(private_key):
    return fast_pow(G, private_key, P)

def shared_secret(peer_public, private_key):
    if not 1 < peer_public < P:
        raise ValueError("对方公开值不在合法范围内")
    return fast_pow(peer_public, private_key, P)

def derive_material(secret):
    raw = secret.to_bytes((secret.bit_length() + 7) // 8 or 1, "big")
    aes_key = hmac.new(raw, b"DH-TCP-AES-128", hashlib.sha256).digest()[:16]
    mac_key = hmac.new(raw, b"DH-TCP-HMAC-SHA256", hashlib.sha256).digest()
    return aes_key, mac_key

def send_frame(sock, payload):
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("连接在数据接收完成前关闭")
        data.extend(part)
    return bytes(data)

def recv_frame(sock):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > 1024 * 1024:
        raise ValueError("单帧数据超过安全上限")
    return json.loads(recv_exact(sock, size).decode())

def encrypt_message(text, aes_key, mac_key):
    cipher = aes.encrypt(text.encode("utf-8"), aes_key)
    tag = hmac.new(mac_key, cipher, hashlib.sha256).hexdigest()
    return {"ciphertext": cipher.hex(), "hmac": tag}

def decrypt_message(packet, aes_key, mac_key):
    cipher = bytes.fromhex(packet["ciphertext"])
    expected = hmac.new(mac_key, cipher, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, packet["hmac"]):
        raise ValueError("HMAC 校验失败：密文可能被篡改")
    return aes.decrypt(cipher, aes_key).decode("utf-8")

def transcript_hash(alice_public, bob_public):
    text = f"{P}|{G}|{alice_public}|{bob_public}".encode()
    return hashlib.sha256(text).hexdigest()[:16]
