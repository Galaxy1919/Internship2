"""加密端（TCP 客户端）：交换 DH 公开值，派生 AES 密钥并发送加密消息。"""
import argparse
import socket
from dh_socket_common import (
    P, G, public_value, shared_secret, derive_material,
    send_frame, recv_frame, encrypt_message, transcript_hash,
)

ALICE_PRIVATE = 1234

def send_encrypted(message, host="127.0.0.1", port=29090):
    alice_public = public_value(ALICE_PRIVATE)
    with socket.create_connection((host,port), timeout=5) as sock:
        send_frame(sock,{"type":"dh_hello","p":P,"g":G,"public":alice_public})
        reply=recv_frame(sock)
        if reply.get("type") != "dh_reply": raise ValueError("没有收到合法 DH 响应")
        bob_public=int(reply["public"])
        secret=shared_secret(bob_public,ALICE_PRIVATE)
        aes_key,mac_key=derive_material(secret)
        session=transcript_hash(alice_public,bob_public)
        if reply.get("session") != session: raise ValueError("DH 交换记录指纹不一致")
        packet=encrypt_message(message,aes_key,mac_key)
        packet.update({"type":"encrypted_message","session":session})
        send_frame(sock,packet)
        ack=recv_frame(sock)
        if ack.get("status") != "PASS" or ack.get("session") != session: raise ValueError("解密端确认失败")
        print(f"DH_SHARED {secret}")
        print(f"SESSION {session}")
        print(f"CIPHERTEXT {packet['ciphertext']}")
        print("SERVER_ACK PASS")
        return packet

if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("message",nargs="?",default="DH交换成功，这是一条AES加密消息"); parser.add_argument("--host",default="127.0.0.1"); parser.add_argument("--port",type=int,default=29090)
    args=parser.parse_args(); send_encrypted(args.message,args.host,args.port)
