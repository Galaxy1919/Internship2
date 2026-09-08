"""加密端（TCP 客户端）：交换 DH 公开值，派生 AES 密钥并发送加密消息或文件。"""
import argparse
import socket
from pathlib import Path
from dh_socket_common import (
    P, G, public_value, shared_secret, derive_material,
    send_frame, recv_frame, encrypt_message, transcript_hash,
    send_file_chunks,
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("message", nargs="?", default="DH交换成功，这是一条AES加密消息")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=29090)
    parser.add_argument("--file", dest="path", help="发送文件（而非消息）")
    parser.add_argument("--plain", action="store_true", help="文件不加密、明文传输")
    args = parser.parse_args()
    if args.path:
        send_file(args.path, args.host, args.port, encrypt=not args.plain)
    else:
        send_encrypted(args.message, args.host, args.port)
