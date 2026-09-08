"""加密端（TCP 客户端）：交换 DH 公开值，派生 AES 密钥并发送加密消息 / 文件 / 任意密码密文。"""
import argparse
import json
import socket
from pathlib import Path
from dh_socket_common import (
    P, G, public_value, shared_secret, derive_material,
    send_frame, recv_frame, encrypt_message, transcript_hash,
    send_file_chunks,
)
from cipher_registry import (
    get as get_cipher, list_ciphers,
    get_pubkey, list_pubkey_ciphers, md5_hex,
    ecc_generate_keypair, ecc_ecdh, ecc_point_serialize, ecc_point_parse,
)

ALICE_PRIVATE = 1234


def connect_and_handshake(host, port):
    """建立 TCP 连接并完成 DH 密钥交换，返回 (sock, secret, aes_key, mac_key, session)。"""
    alice_public = public_value(ALICE_PRIVATE)
    sock = socket.create_connection((host, port), timeout=10)
    send_frame(sock, {"type": "dh_hello", "p": P, "g": G, "public": alice_public})
    reply = recv_frame(sock)
    if reply.get("type") != "dh_reply":
        sock.close()
        raise ValueError("没有收到合法 DH 响应")
    bob_public = int(reply["public"])
    secret = shared_secret(bob_public, ALICE_PRIVATE)
    aes_key, mac_key = derive_material(secret)
    session = transcript_hash(alice_public, bob_public)
    if reply.get("session") != session:
        sock.close()
        raise ValueError("DH 交换记录指纹不一致")
    return sock, secret, aes_key, mac_key, session


def send_encrypted(message, host="127.0.0.1", port=29090):
    sock, secret, aes_key, mac_key, session = connect_and_handshake(host, port)
    with sock:
        packet = encrypt_message(message, aes_key, mac_key)
        packet.update({"type": "encrypted_message", "session": session})
        send_frame(sock, packet)
        ack = recv_frame(sock)
        if ack.get("status") != "PASS" or ack.get("session") != session:
            raise ValueError("解密端确认失败")
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"CIPHERTEXT {packet['ciphertext']}")
        print("SERVER_ACK PASS")
        return packet


def send_file(path, host="127.0.0.1", port=29090, encrypt=True):
    """发送一个文件；encrypt=True 时用 DH 派生的 AES 密钥加密传输。"""
    data = Path(path).read_bytes()
    filename = Path(path).name
    sock, secret, aes_key, mac_key, session = connect_and_handshake(host, port)
    with sock:
        send_frame(sock, {"type": "file_meta", "filename": filename,
                          "size": len(data), "encrypted": encrypt, "session": session})
        send_file_chunks(sock, data,
                         aes_key if encrypt else None,
                         mac_key if encrypt else None)
        ack = recv_frame(sock)
        if ack.get("status") != "PASS" or ack.get("session") != session:
            raise ValueError("解密端确认失败")
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"FILE {filename}")
        print(f"FILE_SIZE {len(data)}")
        print("SERVER_ACK PASS")
        return ack


def send_cipher_message(cipher_id, text, key=None, host="127.0.0.1", port=29090):
    """加密端选任意密码算法，加密后经传输层(DH+AES)发给解密端。

    流程：本地用所选算法加密 -> 装进信封 {cipher, key, payload} -> 整个信封
    用传输层 AES+HMAC 再加密一次 -> 发送。解密端解密传输层后按 cipher 分派。
    """
    cipher = get_cipher(cipher_id)
    key_bytes = cipher["make_key"](key)
    payload = text.encode("utf-8")
    ciphertext = cipher["encrypt"](payload, key_bytes)
    envelope = {"cipher": cipher_id, "key": key_bytes.hex(), "payload": ciphertext.hex()}
    sock, secret, aes_key, mac_key, session = connect_and_handshake(host, port)
    with sock:
        packet = encrypt_message(json.dumps(envelope, ensure_ascii=False), aes_key, mac_key)
        packet.update({"type": "cipher_message", "session": session})
        send_frame(sock, packet)
        ack = recv_frame(sock)
        if ack.get("status") != "PASS" or ack.get("session") != session:
            raise ValueError("解密端确认失败")
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"CIPHER {cipher['label']}")
        print(f"KEY {key_bytes.hex()}")
        print(f"CIPHERTEXT {ciphertext.hex()}")
        print("SERVER_ACK PASS")
        return ack


def send_pubkey_message(cipher_id, text, host="127.0.0.1", port=29090):
    """公钥密码（反向密钥流）：先向解密端要公钥，用公钥加密后发回，解密端用私钥解。"""
    pub = get_pubkey(cipher_id)
    sock, secret, aes_key, mac_key, session = connect_and_handshake(host, port)
    with sock:
        send_frame(sock, {"type": "pubkey_request", "cipher": cipher_id, "session": session})
        reply = recv_frame(sock)
        if reply.get("type") != "pubkey_reply" or reply.get("session") != session:
            raise ValueError("未收到合法公钥响应")
        pub_str = reply["public_key"]
        ciphertext = pub["encrypt"](text.encode("utf-8"), pub_str)
        packet = encrypt_message(ciphertext.hex(), aes_key, mac_key)
        packet.update({"type": "pubkey_message", "cipher": cipher_id, "session": session})
        send_frame(sock, packet)
        ack = recv_frame(sock)
        if ack.get("status") != "PASS" or ack.get("session") != session:
            raise ValueError("解密端确认失败")
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"CIPHER {pub['label']}")
        print(f"PUBLIC_KEY {pub_str}")
        print(f"CIPHERTEXT {ciphertext.hex()}")
        print("SERVER_ACK PASS")
        return ack


def send_digest(text, host="127.0.0.1", port=29090):
    """发送「消息 + MD5 摘要」，解密端重算摘要做完整性校验。"""
    sock, secret, aes_key, mac_key, session = connect_and_handshake(host, port)
    with sock:
        digest = md5_hex(text.encode("utf-8"))
        envelope = json.dumps({"message": text, "digest": digest}, ensure_ascii=False)
        packet = encrypt_message(envelope, aes_key, mac_key)
        packet.update({"type": "digest_verify", "session": session})
        send_frame(sock, packet)
        ack = recv_frame(sock)
        if ack.get("status") != "PASS" or ack.get("session") != session:
            raise ValueError("解密端确认失败")
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"DIGEST {digest}")
        print("SERVER_ACK PASS")
        return ack


def run_ecdh(host="127.0.0.1", port=29090):
    """ECC(secp256k1) ECDH 密钥交换：双方交换公钥，各自算出同一个共享点。"""
    dA, QA = ecc_generate_keypair()
    sock, secret, aes_key, mac_key, session = connect_and_handshake(host, port)
    with sock:
        send_frame(sock, {"type": "ecdh_hello", "public": ecc_point_serialize(QA), "session": session})
        reply = recv_frame(sock)
        if reply.get("type") != "ecdh_reply" or reply.get("session") != session:
            raise ValueError("未收到合法 ECDH 响应")
        QB = ecc_point_parse(reply["public"])
        SA = ecc_ecdh(dA, QB)
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"ECDH_SHARED {SA[0]:x}")
        return SA


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("message", nargs="?", default="DH交换成功，这是一条AES加密消息")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=29090)
    parser.add_argument("--file", dest="path", help="发送文件（而非消息）")
    parser.add_argument("--plain", action="store_true", help="文件不加密、明文传输")
    parser.add_argument("--cipher", choices=[cid for cid, _ in list_ciphers()],
                        help="选择密码算法加密发送（可选: %(choices)s）")
    parser.add_argument("--text", help="用 --cipher/--pubkey/--digest 时要发送的明文")
    parser.add_argument("--key", help="密码算法的密钥字符串（缺省自动生成/用默认词）")
    parser.add_argument("--pubkey", choices=[cid for cid, _ in list_pubkey_ciphers()],
                        help="选择公钥密码加密发送（可选: %(choices)s）")
    parser.add_argument("--digest", action="store_true", help="发送 MD5 摘要做完整性校验（配合 --text）")
    parser.add_argument("--ecdh", action="store_true", help="ECC(secp256k1) ECDH 密钥交换")
    args = parser.parse_args()

    if args.pubkey:
        if args.text is None:
            parser.error("--pubkey 需要配合 --text 指定明文")
        send_pubkey_message(args.pubkey, args.text, host=args.host, port=args.port)
    elif args.digest:
        if args.text is None:
            parser.error("--digest 需要配合 --text 指定明文")
        send_digest(args.text, host=args.host, port=args.port)
    elif args.ecdh:
        run_ecdh(args.host, args.port)
    elif args.cipher:
        if args.text is None:
            parser.error("--cipher 需要配合 --text 指定明文")
        send_cipher_message(args.cipher, args.text, key=args.key,
                            host=args.host, port=args.port)
    elif args.path:
        send_file(args.path, args.host, args.port, encrypt=not args.plain)
    else:
        send_encrypted(args.message, args.host, args.port)
