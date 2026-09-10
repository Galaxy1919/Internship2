"""解密端（TCP 服务端）：交换 DH 公开值，验证会话并按帧类型分派（消息/文件/对称密码/公钥/摘要/ECDH）。"""
import argparse
import json
import socket
from pathlib import Path
from dh_socket_common import (
    P, G, public_value, shared_secret, derive_material,
    send_frame, recv_frame, decrypt_message, transcript_hash,
    recv_file_chunks, TRANSPORT_CIPHERS,
    sign_transcript, BOB_IDENTITY_D, BOB_IDENTITY_PUB, BOB_IDENTITY_PUB_STR,
)
from cipher_registry import (
    get as get_cipher,
    get_pubkey,
    md5_hex,
    ecc_generate_keypair,
    ecc_ecdh,
    ecc_point_serialize,
    ecc_point_parse,
)

BOB_PRIVATE = 5678
OUT_DIR = Path(__file__).resolve().parent / "received"


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
                transport = hello.get("transport", "aes")
                if transport not in TRANSPORT_CIPHERS:
                    raise ValueError(f"不支持的传输密码: {transport}")
                alice_public = int(hello["public"])
                secret = shared_secret(alice_public, BOB_PRIVATE)
                tkey, mac_key = derive_material(secret, transport)
                session = transcript_hash(alice_public, bob_public)
                signature = sign_transcript(BOB_IDENTITY_D, BOB_IDENTITY_PUB,
                                            alice_public, bob_public)
                send_frame(conn, {"type": "dh_reply", "public": bob_public,
                                  "session": session, "signature": signature,
                                  "identity_pub": BOB_IDENTITY_PUB_STR})

                pubkey_priv = None      # 会话内公钥密码的私钥 (cipher_id, private)
                expected_seq = 0        # 重放保护：JSON 帧序号严格递增
                while True:             # 会话内多帧循环，直到一个终结帧
                    packet = recv_frame(conn)
                    if packet.get("session") != session:
                        raise ValueError("会话编号不匹配")
                    seq = packet.get("seq")
                    if seq != expected_seq:
                        raise ValueError(f"重放/乱序检测：期望 seq={expected_seq}，收到 {seq}")
                    expected_seq += 1
                    t = packet.get("type")

                    if t == "encrypted_message":
                        plaintext = decrypt_message(packet, tkey, mac_key, transport)
                        print(f"CLIENT {address[0]}:{address[1]}")
                        print(f"DH_SHARED {secret}")
                        print(f"SESSION {session}")
                        print(f"TRANSPORT {transport}")
                        print(f"PLAINTEXT {plaintext}")
                        send_frame(conn, {"type": "ack", "session": session, "status": "PASS"})
                        break

                    elif t == "file_meta":
                        filename = Path(packet.get("filename", "unnamed")).name
                        encrypted = bool(packet.get("encrypted", True))
                        data = recv_file_chunks(conn,
                                                tkey if encrypted else None,
                                                mac_key if encrypted else None, transport)
                        OUT_DIR.mkdir(exist_ok=True)
                        out_path = OUT_DIR / filename
                        out_path.write_bytes(data)
                        print(f"CLIENT {address[0]}:{address[1]}")
                        print(f"DH_SHARED {secret}")
                        print(f"SESSION {session}")
                        print(f"TRANSPORT {transport}")
                        print(f"FILE {filename}")
                        print(f"FILE_SIZE {len(data)}")
                        print(f"FILE_SAVED {out_path}")
                        send_frame(conn, {"type": "file_ack", "session": session,
                                          "status": "PASS", "size": len(data)})
                        break

                    elif t == "cipher_message":
                        envelope = json.loads(decrypt_message(packet, tkey, mac_key, transport))
                        cipher = get_cipher(envelope["cipher"])
                        key = bytes.fromhex(envelope["key"])
                        payload = bytes.fromhex(envelope["payload"])
                        plaintext = cipher["decrypt"](payload, key).decode("utf-8", errors="replace")
                        print(f"CLIENT {address[0]}:{address[1]}")
                        print(f"DH_SHARED {secret}")
                        print(f"SESSION {session}")
                        print(f"TRANSPORT {transport}")
                        print(f"CIPHER {cipher['label']}")
                        print(f"PLAINTEXT {plaintext}")
                        send_frame(conn, {"type": "ack", "session": session, "status": "PASS"})
                        break

                    elif t == "pubkey_request":
                        # 反向密钥流第一步：解密端生成密钥对，把公钥发回加密端
                        pub = get_pubkey(packet["cipher"])
                        priv, pub_str = pub["generate"]()
                        pubkey_priv = (packet["cipher"], priv)
                        send_frame(conn, {"type": "pubkey_reply", "cipher": packet["cipher"],
                                          "public_key": pub_str, "session": session})
                        continue

                    elif t == "pubkey_message":
                        if pubkey_priv is None:
                            raise ValueError("收到 pubkey_message 但未先收到 pubkey_request")
                        cipher_id, priv = pubkey_priv
                        pub = get_pubkey(cipher_id)
                        ct = bytes.fromhex(decrypt_message(packet, tkey, mac_key, transport))
                        plaintext = pub["decrypt"](ct, priv).decode("utf-8", errors="replace")
                        print(f"CLIENT {address[0]}:{address[1]}")
                        print(f"DH_SHARED {secret}")
                        print(f"SESSION {session}")
                        print(f"TRANSPORT {transport}")
                        print(f"CIPHER {pub['label']}")
                        print(f"PLAINTEXT {plaintext}")
                        send_frame(conn, {"type": "ack", "session": session, "status": "PASS"})
                        break

                    elif t == "digest_verify":
                        env = json.loads(decrypt_message(packet, tkey, mac_key, transport))
                        recomputed = md5_hex(env["message"].encode("utf-8"))
                        match = recomputed == env["digest"]
                        print(f"CLIENT {address[0]}:{address[1]}")
                        print(f"DH_SHARED {secret}")
                        print(f"SESSION {session}")
                        print(f"TRANSPORT {transport}")
                        print(f"DIGEST {env['digest']}")
                        print(f"DIGEST_RECOMPUTED {recomputed}")
                        print(f"DIGEST_MATCH {'PASS' if match else 'FAIL'}")
                        send_frame(conn, {"type": "ack", "session": session, "status": "PASS"})
                        break

                    elif t == "ecdh_hello":
                        dB, QB = ecc_generate_keypair()
                        QA = ecc_point_parse(packet["public"])
                        SB = ecc_ecdh(dB, QA)
                        send_frame(conn, {"type": "ecdh_reply", "public": ecc_point_serialize(QB),
                                          "session": session})
                        print(f"CLIENT {address[0]}:{address[1]}")
                        print(f"DH_SHARED {secret}")
                        print(f"SESSION {session}")
                        print(f"TRANSPORT {transport}")
                        print(f"ECDH_SHARED {SB[0]:x}")
                        break

                    else:
                        raise ValueError(f"未知的消息类型: {t}")
            if once:
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=29090)
    args = parser.parse_args()
    serve(args.host, args.port)
