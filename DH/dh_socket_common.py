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


# ---------------------------------------------------------------------------
# 文件传输（分块流式，可选 AES 加密 + HMAC 完整性校验）
# ---------------------------------------------------------------------------

CHUNK_SIZE = 64 * 1024      # 每块 64KB，避免大文件一次性读入内存
TAG_LEN = 64                # sha256 hexdigest 长度（HMAC 标签）

def send_bytes(sock, data):
    """发送一个长度前缀的二进制帧（与 send_frame 的 JSON 帧互补，用于大块数据）。"""
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_bytes(sock):
    """接收一个长度前缀的二进制帧，返回原始字节。"""
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > 64 * 1024 * 1024:
        raise ValueError("单帧数据超过安全上限")
    return recv_exact(sock, size)


def encrypt_chunk(chunk, aes_key, mac_key):
    """对一块数据做 AES 加密 + HMAC，返回 cipher || tag（tag 固定 64 字节十六进制）。"""
    cipher = aes.encrypt(chunk, aes_key)
    tag = hmac.new(mac_key, cipher, hashlib.sha256).hexdigest().encode("ascii")
    return cipher + tag


def decrypt_chunk(blob, aes_key, mac_key):
    """校验 HMAC 并 AES 解密一块数据，返回明文。"""
    cipher, tag = blob[:-TAG_LEN], blob[-TAG_LEN:].decode("ascii")
    expected = hmac.new(mac_key, cipher, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("HMAC 校验失败：文件块可能被篡改")
    return aes.decrypt(cipher, aes_key)


def send_file_chunks(sock, data, aes_key=None, mac_key=None):
    """把一段完整字节流分块发出；每块可选加密；末尾发空帧作为 EOF。"""
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i + CHUNK_SIZE]
        payload = encrypt_chunk(chunk, aes_key, mac_key) if (aes_key and mac_key) else chunk
        send_bytes(sock, payload)
    send_bytes(sock, b"")       # 空帧 = EOF 结束标记


def recv_file_chunks(sock, aes_key=None, mac_key=None):
    """接收分块字节流直到 EOF 空帧，返回完整字节；每块可选解密。"""
    parts = []
    while True:
        payload = recv_bytes(sock)
        if not payload:
            break
        parts.append(decrypt_chunk(payload, aes_key, mac_key) if (aes_key and mac_key) else payload)
    return b"".join(parts)
