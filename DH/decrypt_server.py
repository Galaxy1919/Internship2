"""解密端（TCP 服务端）：交换 DH 公开值，验证会话并解密 AES 消息。"""
import argparse
import socket
from dh_socket_common import (
    P, G, public_value, shared_secret, derive_material,
    send_frame, recv_frame, decrypt_message, transcript_hash,
)

BOB_PRIVATE = 5678

def serve(host="127.0.0.1", port=29090, once=True):
    bob_public = public_value(BOB_PRIVATE)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port)); server.listen(1)
        print(f"READY {host}:{port}", flush=True)
        while True:
            conn, address = server.accept()
            with conn:
                hello = recv_frame(conn)
                if hello.get("type") != "dh_hello" or hello.get("p") != P or hello.get("g") != G:
                    raise ValueError("DH 公共参数不一致")
                alice_public = int(hello["public"])
                secret = shared_secret(alice_public, BOB_PRIVATE)
                aes_key, mac_key = derive_material(secret)
                session = transcript_hash(alice_public, bob_public)
                send_frame(conn, {"type":"dh_reply", "public":bob_public, "session":session})
                packet = recv_frame(conn)
                if packet.get("type") != "encrypted_message" or packet.get("session") != session:
                    raise ValueError("会话编号不匹配")
                plaintext = decrypt_message(packet, aes_key, mac_key)
                print(f"CLIENT {address[0]}:{address[1]}")
                print(f"DH_SHARED {secret}")
                print(f"SESSION {session}")
                print(f"PLAINTEXT {plaintext}")
                send_frame(conn, {"type":"ack", "session":session, "status":"PASS"})
            if once: break

if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--host",default="127.0.0.1"); parser.add_argument("--port",type=int,default=29090)
    args=parser.parse_args(); serve(args.host,args.port)
