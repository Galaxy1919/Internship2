"""DH-TCP 实验公共模块：参数、快速模幂、密钥派生、长度帧协议与传输加密封装。

传输密码可动态指定（默认 aes，可选 des/rc4/ca）：DH 协商出共享秘密后，用 KDF
派生出所选密码所需长度的密钥，再加 HMAC 做完整性校验。这样「至少一个密码用
DH 交换密钥」的要求对任意所选传输密码都成立，无需写死 AES。
"""
import hashlib
import hmac
import json
import struct
from pathlib import Path

from cipher_registry import get as get_cipher, SM2 as SM2_MODULE

P = 7919
G = 5

# 传输层可选密码（bytes 型对称密码；古典字符串密码不适合二进制传输）
TRANSPORT_CIPHERS = ("aes", "des", "rc4", "ca")
TRANSPORT_KEY_LEN = {"aes": 16, "des": 8, "rc4": 16, "ca": 16}
FRAME_SIZE_LIMIT = 1024 * 1024
BINARY_FRAME_SIZE_LIMIT = 64 * 1024 * 1024


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


def _kdf(secret, label, length):
    """HMAC-SHA256 密钥派生，输出指定长度字节。"""
    seed = secret.to_bytes((secret.bit_length() + 7) // 8 or 1, "big")
    out = bytearray()
    counter = 1
    while len(out) < length:
        out.extend(hmac.new(seed, label.encode() + bytes([counter]), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def derive_material(secret, cipher_id="aes"):
    """DH 共享秘密派生传输密码所需长度的密钥 + HMAC 密钥。"""
    if cipher_id not in TRANSPORT_CIPHERS:
        raise ValueError(f"传输密码必须是 {TRANSPORT_CIPHERS} 之一，收到 {cipher_id}")
    key = _kdf(secret, f"DH-TCP-{cipher_id.upper()}", TRANSPORT_KEY_LEN[cipher_id])
    mac_key = _kdf(secret, "DH-TCP-HMAC-SHA256", 32)
    return key, mac_key


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
    if size > FRAME_SIZE_LIMIT:
        raise ValueError("单帧数据超过安全上限")
    return json.loads(recv_exact(sock, size).decode())


def encrypt_message(text, key, mac_key, cipher_id="aes"):
    """用传输密码加密一段文本，附 HMAC。"""
    cipher = get_cipher(cipher_id)
    ciphertext = cipher["encrypt"](text.encode("utf-8"), key)
    tag = hmac.new(mac_key, ciphertext, hashlib.sha256).hexdigest()
    return {"ciphertext": ciphertext.hex(), "hmac": tag}


def decrypt_message(packet, key, mac_key, cipher_id="aes"):
    """校验 HMAC 并用传输密码解密。"""
    cipher = get_cipher(cipher_id)
    ct = bytes.fromhex(packet["ciphertext"])
    expected = hmac.new(mac_key, ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, packet["hmac"]):
        raise ValueError("HMAC 校验失败：密文可能被篡改")
    return cipher["decrypt"](ct, key).decode("utf-8")


def _transcript_bytes(alice_public, bob_public):
    return f"{P}|{G}|{alice_public}|{bob_public}".encode()


def transcript_hash(alice_public, bob_public):
    text = _transcript_bytes(alice_public, bob_public)
    return hashlib.sha256(text).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 认证 DH（防中间人）：Bob 用长期 SM2 身份密钥对 DH 交换 transcript 做签名，
# Alice 持 Bob 公钥验签。原始 DH 不认证身份，中间人可替换双方公开值；加了
# 签名后，中间人无法伪造 Bob 的签名，篡改公开值会立即被 Alice 识破。
# ---------------------------------------------------------------------------

# Bob 的长期身份密钥对（教学用固定值，由固定种子确定性派生，保证可复现）
_BOB_IDENTITY_SEED = b"bob-long-term-identity-key"
BOB_IDENTITY_D = (int.from_bytes(SM2_MODULE.sm3(_BOB_IDENTITY_SEED), "big")
                  % (SM2_MODULE.SM2.n - 1) + 1)
BOB_IDENTITY_PUB = SM2_MODULE.scalar_mul(BOB_IDENTITY_D, SM2_MODULE.SM2.G)
BOB_IDENTITY_PUB_STR = f"{BOB_IDENTITY_PUB[0]}:{BOB_IDENTITY_PUB[1]}"


def sign_transcript(priv_d, pub, alice_public, bob_public):
    """Bob 对 DH 交换 transcript 做 SM2 签名，返回 "r:s" 字符串。"""
    msg = _transcript_bytes(alice_public, bob_public)
    r, s = SM2_MODULE.sign(msg, priv_d, pub)
    return f"{r}:{s}"


def verify_transcript(sig_str, pub, alice_public, bob_public):
    """Alice 用 Bob 公钥验签，确认 DH 公开值确实来自 Bob（而非中间人）。"""
    msg = _transcript_bytes(alice_public, bob_public)
    r, s = (int(v) for v in sig_str.split(":"))
    return SM2_MODULE.verify(msg, (r, s), pub)


def parse_pubkey(pub_str):
    """把 "x:y" 十进制字符串还原成 (x, y) int 元组。"""
    x, y = (int(v) for v in pub_str.split(":"))
    return x, y


# ---------------------------------------------------------------------------
# 文件传输（分块流式，可选传输密码加密 + HMAC 完整性校验）
# ---------------------------------------------------------------------------

CHUNK_SIZE = 64 * 1024      # 每块 64KB，避免大文件一次性读入内存
TAG_LEN = 64                # sha256 hexdigest 长度（HMAC 标签）
MAX_FILE_SIZE = 256 * 1024 * 1024

def send_bytes(sock, data):
    """发送一个长度前缀的二进制帧（与 send_frame 的 JSON 帧互补，用于大块数据）。"""
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_bytes(sock):
    """接收一个长度前缀的二进制帧，返回原始字节。"""
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > BINARY_FRAME_SIZE_LIMIT:
        raise ValueError("单帧数据超过安全上限")
    return recv_exact(sock, size)


def encrypt_chunk(chunk, key, mac_key, cipher_id="aes"):
    """对一块数据做传输密码加密 + HMAC，返回 cipher || tag（tag 固定 64 字节十六进制）。"""
    ct = get_cipher(cipher_id)["encrypt"](chunk, key)
    tag = hmac.new(mac_key, ct, hashlib.sha256).hexdigest().encode("ascii")
    return ct + tag


def decrypt_chunk(blob, key, mac_key, cipher_id="aes"):
    """校验 HMAC 并解密一块数据，返回明文。"""
    if len(blob) <= TAG_LEN:
        raise ValueError("文件块长度不足")
    ct, tag = blob[:-TAG_LEN], blob[-TAG_LEN:].decode("ascii")
    expected = hmac.new(mac_key, ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("HMAC 校验失败：文件块可能被篡改")
    return get_cipher(cipher_id)["decrypt"](ct, key)


def send_file_chunks(sock, data, key=None, mac_key=None, cipher_id="aes"):
    """把一段完整字节流分块发出；每块可选加密；末尾发空帧作为 EOF。"""
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i + CHUNK_SIZE]
        payload = encrypt_chunk(chunk, key, mac_key, cipher_id) if (key and mac_key) else chunk
        send_bytes(sock, payload)
    send_bytes(sock, b"")       # 空帧 = EOF 结束标记


def send_file_stream(sock, file_obj, size, key=None, mac_key=None, cipher_id="aes"):
    """从文件对象分块发送文件，不把完整文件读入内存。"""
    if size < 0 or size > MAX_FILE_SIZE:
        raise ValueError("文件大小超过安全上限")
    remaining = size
    while remaining:
        chunk = file_obj.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise IOError("文件在发送过程中长度发生变化")
        remaining -= len(chunk)
        payload = encrypt_chunk(chunk, key, mac_key, cipher_id) if (key and mac_key) else chunk
        send_bytes(sock, payload)
    if file_obj.read(1):
        raise IOError("文件在发送过程中长度发生变化")
    send_bytes(sock, b"")


def recv_file_chunks(sock, key=None, mac_key=None, cipher_id="aes"):
    """接收分块字节流直到 EOF 空帧，返回完整字节；每块可选解密。"""
    parts = []
    while True:
        payload = recv_bytes(sock)
        if not payload:
            break
        parts.append(decrypt_chunk(payload, key, mac_key, cipher_id) if (key and mac_key) else payload)
    return b"".join(parts)


def recv_file_to(sock, file_obj, expected_size, key=None, mac_key=None, cipher_id="aes"):
    """接收文件分块并直接写入文件对象，同时校验声明大小。"""
    if not isinstance(expected_size, int) or isinstance(expected_size, bool):
        raise ValueError("文件大小字段必须是整数")
    if expected_size < 0 or expected_size > MAX_FILE_SIZE:
        raise ValueError("文件大小超过安全上限")
    received = 0
    while True:
        payload = recv_bytes(sock)
        if not payload:
            break
        chunk = decrypt_chunk(payload, key, mac_key, cipher_id) if (key and mac_key) else payload
        received += len(chunk)
        if received > expected_size:
            raise ValueError("实际接收文件超过声明大小")
        file_obj.write(chunk)
    if received != expected_size:
        raise ValueError(f"文件大小不一致：声明 {expected_size}，实际 {received}")
    return received
