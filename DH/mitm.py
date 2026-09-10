#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中间人（MITM）攻击演示 —— 认证 DH 的攻防对照。

原始 DH 不认证身份：中间人 Eve 可以分别和 Alice、Bob 各做一次 DH，
把双方隔开，各自以为在跟对方通信，实则明文被 Eve 全部看到。

本脚本把 Eve 插在 Alice 与 Bob 之间：
  1. 用同一个公开值 M 替换 Alice 看到的「Bob 公开值」和 Bob 看到的「Alice 公开值」；
  2. 分别与双方算出共享密钥；
  3. 解密 Alice 发来的密文（攻击成功），再重新加密转发给 Bob。

对照实验：
  - Alice 用 --no-auth 启动 → Eve 解密成功，攻击得逞；
  - Alice 用默认（认证 DH）启动 → 验签失败，Alice 主动断开，攻击被识破。

用法：
  # 1) 起真实 Bob
  python3 decrypt_server.py --port 29090
  # 2) 起中间人 Eve（转发到 29090）
  python3 mitm.py --mitm-port 39000 --target-port 29090
  # 3) Alice 连到 Eve（--no-auth 观察攻击成功；去掉 --no-auth 观察被识破）
  python3 encrypt_client.py "绝密消息" --host 127.0.0.1 --port 39000 --no-auth
"""
import argparse
import socket

from dh_socket_common import (
    public_value, shared_secret, derive_material,
    send_frame, recv_frame, encrypt_message, decrypt_message,
    transcript_hash, TRANSPORT_CIPHERS,
)

MITM_PRIVATE = 9999          # Eve 的 DH 私钥（固定，教学用）


def mitm(mitm_host, mitm_port, target_host, target_port, transport="aes"):
    if transport not in TRANSPORT_CIPHERS:
        raise ValueError(f"传输密码必须是 {TRANSPORT_CIPHERS} 之一")
    M = public_value(MITM_PRIVATE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((mitm_host, mitm_port))
        server.listen(1)
        print(f"[Eve] 中间人已就位：监听 {mitm_host}:{mitm_port}，转发到 Bob {target_host}:{target_port}", flush=True)

        alice_conn, _ = server.accept()
        bob_conn = socket.create_connection((target_host, target_port))
        with alice_conn, bob_conn:
            # --- 阶段 1：转发 Alice 的 dh_hello，把 Alice 的公开值换成 M ---
            hello = recv_frame(alice_conn)
            alice_public = int(hello["public"])
            print(f"[Eve] 截获 Alice 的 DH 公开值 A={alice_public}，替换成自己的 M={M}")
            hello["public"] = M
            send_frame(bob_conn, hello)

            # --- 阶段 2：转发 Bob 的 dh_reply，把 Bob 的公开值换成 M ---
            reply = recv_frame(bob_conn)
            bob_public = int(reply["public"])
            print(f"[Eve] 截获 Bob 的 DH 公开值 B={bob_public}，替换成自己的 M={M}")
            session_A = transcript_hash(alice_public, M)      # 给 Alice 看的会话号
            session_B = transcript_hash(M, bob_public)        # 给 Bob 看的会话号
            # 注意：signature 原样转发，但它是对 transcript(M,B) 签的，Alice 会验签失败
            send_frame(alice_conn, {"type": "dh_reply", "public": M, "session": session_A,
                                    "signature": reply.get("signature"),
                                    "identity_pub": reply.get("identity_pub")})

            # --- 阶段 3：与双方分别派生共享密钥 ---
            secret_A = shared_secret(alice_public, MITM_PRIVATE)   # 与 Alice 共享
            secret_B = shared_secret(bob_public, MITM_PRIVATE)     # 与 Bob 共享
            tkey_A, mac_A = derive_material(secret_A, transport)
            tkey_B, mac_B = derive_material(secret_B, transport)
            print(f"[Eve] 与 Alice 的共享密钥 K_A={secret_A}，与 Bob 的共享密钥 K_B={secret_B}")

            # --- 阶段 4：尝试解密 Alice 发来的帧 ---
            try:
                packet = recv_frame(alice_conn)
            except ConnectionError:
                print("[Eve] Alice 已主动断开 —— 认证 DH 验签失败，中间人攻击被识破 ✗")
                return

            if packet.get("type") != "encrypted_message":
                print(f"[Eve] 收到帧类型 {packet.get('type')}，本演示只解 encrypted_message")
                return

            plaintext = decrypt_message(packet, tkey_A, mac_A, transport)
            print(f"[Eve] ★ 攻击成功：用与 Alice 的共享密钥解密得到明文 = {plaintext!r}")

            # 重新加密转发给 Bob（把 seq 重写为 0，session 重写为 Bob 的会话号）
            fwd = encrypt_message(plaintext, tkey_B, mac_B, transport)
            fwd.update({"type": "encrypted_message", "session": session_B, "seq": 0})
            send_frame(bob_conn, fwd)
            ack = recv_frame(bob_conn)
            print(f"[Eve] 已把明文重新加密转发给 Bob，Bob 确认: {ack.get('status')}")
            # 把 ack 的 session 改回 Alice 的会话号再回传
            ack["session"] = session_A
            send_frame(alice_conn, ack)
            print("[Eve] 攻击全程完成：Alice 与 Bob 全程无感知 ✗（原始 DH 不安全）")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="中间人攻击演示（认证 DH 攻防对照）")
    parser.add_argument("--mitm-host", default="127.0.0.1")
    parser.add_argument("--mitm-port", type=int, default=39000)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=29090)
    parser.add_argument("--transport", choices=list(TRANSPORT_CIPHERS), default="aes")
    args = parser.parse_args()
    mitm(args.mitm_host, args.mitm_port, args.target_host, args.target_port, args.transport)
