from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DH_ROOT = ROOT / "DH"
sys.path.insert(0, str(DH_ROOT))

from cipher_registry import get, get_pubkey, md5_hex  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cipher", required=True)
    p.add_argument("--text", default="HELLO WORLD")
    p.add_argument("--key", default="KEYWORD")
    args = p.parse_args()
    payload = args.text.encode("utf-8")
    if args.cipher == "md5":
        print(f"算法：MD5\n输入：{args.text}\n摘要：{md5_hex(payload)}")
        return 0
    if args.cipher == "dh":
        from main import exchange
        record = exchange()
        print("算法：DH 密钥交换")
        names = {"p": "模数 P", "g": "生成元 G", "alice_private": "Alice 私钥", "bob_private": "Bob 私钥", "alice_public": "Alice 公钥", "bob_public": "Bob 公钥", "alice_secret": "Alice 共享秘密", "bob_secret": "Bob 共享秘密", "same_secret": "共享秘密一致", "secret_sha256": "共享秘密摘要", "aes_key": "派生传输密钥"}
        for key, value in record.items(): print(f"{names.get(key, key)}：{value}")
        return 0
    if args.cipher == "ecc":
        from cipher_registry import ecc_ecdh, ecc_generate_keypair, ecc_point_serialize
        d1, q1 = ecc_generate_keypair()
        d2, q2 = ecc_generate_keypair()
        s1 = ecc_ecdh(d1, q2)
        s2 = ecc_ecdh(d2, q1)
        print(f"算法：ECC / ECDH\nAlice 公钥：{ecc_point_serialize(q1)}\nBob 公钥：{ecc_point_serialize(q2)}\n共享点一致：{'是' if s1 == s2 else '否'}")
        return 0 if s1 == s2 else 1
    if args.cipher in {"rsa", "elgamal", "sm2"}:
        entry = get_pubkey(args.cipher)
        private, public = entry["generate"]()
        ct = entry["encrypt"](payload, public)
        plain = entry["decrypt"](ct, private)
        print(f"算法：{args.cipher.upper()}\n公钥：{public}\n密文：{ct.hex()}\n解密结果：{plain.decode('utf-8', errors='replace')}\n往返验证：{'通过' if plain == payload else '失败'}")
        return 0
    entry = get(args.cipher)
    key = entry["make_key"](args.key)
    ct = entry["encrypt"](payload, key)
    plain = entry["decrypt"](ct, key)
    print(f"算法：{args.cipher}\n密文：{ct.hex()}\n解密结果：{plain.decode('utf-8', errors='replace')}\n往返验证：{'通过' if plain == payload else '失败'}")
    return 0 if plain == payload else 1


if __name__ == "__main__":
    raise SystemExit(main())
