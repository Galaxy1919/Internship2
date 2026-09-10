#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密码原语 CLI —— 供系统内智能 agent 通过命令行调用。

每个子命令 = 一个密码原语，输出统一 JSON，便于 agent 无歧义地提取中间值
传给下一步。内部复用 DH/cipher_registry.py 的适配层与算法模块，不重写算法。

约定（重要，schema 里也会写）：
- 对称密钥：hex 字符串（bytes）
- 公钥：十进制，RSA 为 "n:e"，SM2 为 "x:y"，ElGamal 为 "p:g:y"
- 私钥：十进制，RSA 为 "n:d"，SM2 为 "d"，ElGamal 为 "p:g:x:q"
- 签名：十进制 "r:s"
- 密文 / 摘要 / MAC：hex 字符串
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_mod
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DH_ROOT = ROOT / "DH"
if str(DH_ROOT) not in sys.path:
    sys.path.insert(0, str(DH_ROOT))

from cipher_registry import get, get_pubkey, md5_hex, SM2, ELGAMAL  # noqa: E402

BYTES_CIPHERS = {"aes", "des", "rc4", "ca"}
SYM_CIPHERS = ["aes", "des", "rc4", "ca", "vigenere", "playfair", "multiliteral", "transposition"]
PUBKEY_CIPHERS = ["rsa", "elgamal", "sm2"]
SIGN_CIPHERS = ["sm2"]  # 签名暂只暴露 SM2（SM2-DSA）；RSA/ElGamal 的 sign 需完整 key 对象
HASH_ALGOS = ["md5", "sm3"]


def emit(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False))


def fail(msg: str) -> int:
    emit({"error": msg})
    return 1


# ---------------------------------------------------------------------------
# 密钥的字符串 <-> 内部表示 转换
# ---------------------------------------------------------------------------

def _key_to_str(cipher: str, key_bytes: bytes) -> str:
    """bytes 型密码输出 hex；字符串型（古典）密码输出关键词本身。"""
    if cipher in BYTES_CIPHERS:
        return key_bytes.hex()
    return key_bytes.decode("utf-8", errors="replace")


def _key_from_str(cipher: str, key_str: str) -> bytes:
    """反向：hex -> bytes；关键词 -> UTF-8 bytes。"""
    if cipher in BYTES_CIPHERS:
        return bytes.fromhex(key_str)
    return key_str.encode("utf-8")


# ---------------------------------------------------------------------------
# 对称密码原语
# ---------------------------------------------------------------------------

_KEY_LEN = {"aes": 16, "des": 8, "rc4": 16, "ca": 16}


def cmd_make_key(args) -> int:
    if args.kdf == "pbkdf2":
        if args.cipher not in BYTES_CIPHERS:
            return fail("PBKDF2 仅适用于 bytes 型密码（aes/des/rc4/ca）")
        if not args.seed:
            return fail("PBKDF2 派生需要 --seed 作为口令")
        salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", args.seed.encode("utf-8"), salt,
                                  args.iterations, dklen=_KEY_LEN[args.cipher])
        emit({"cipher": args.cipher, "key": key.hex(), "kdf": "pbkdf2",
              "salt": salt.hex(), "iterations": args.iterations})
        return 0
    entry = get(args.cipher)
    key = entry["make_key"](args.seed if args.seed else None)
    emit({"cipher": args.cipher, "key": _key_to_str(args.cipher, key)})
    return 0


def cmd_sym_encrypt(args) -> int:
    entry = get(args.cipher)
    key = _key_from_str(args.cipher, args.key) if args.key else entry["make_key"](None)
    payload = args.text.encode("utf-8")
    ct = entry["encrypt"](payload, key)
    emit({"cipher": args.cipher, "key": _key_to_str(args.cipher, key), "ciphertext": ct.hex()})
    return 0


def cmd_sym_decrypt(args) -> int:
    entry = get(args.cipher)
    key = _key_from_str(args.cipher, args.key)
    plain = entry["decrypt"](bytes.fromhex(args.ct), key)
    emit({"plaintext": plain.decode("utf-8", errors="replace")})
    return 0


# ---------------------------------------------------------------------------
# 公钥密码原语
# ---------------------------------------------------------------------------

def cmd_pubkey_keygen(args) -> int:
    priv, pub_str = get_pubkey(args.cipher)["generate"]()
    if args.cipher == "rsa":
        n, d = priv
        priv_str = f"{n}:{d}"
    elif args.cipher == "sm2":
        priv_str = str(priv)  # d: int
    else:  # elgamal：ElGamalKey 对象
        priv_str = f"{priv.p}:{priv.g}:{priv.x}:{priv.q}"
    emit({"cipher": args.cipher, "pubkey": pub_str, "privkey": priv_str})
    return 0


def cmd_pubkey_encrypt(args) -> int:
    entry = get_pubkey(args.cipher)
    ct = entry["encrypt"](args.text.encode("utf-8"), args.pubkey)
    emit({"cipher": args.cipher, "ciphertext": ct.hex()})
    return 0


def cmd_pubkey_decrypt(args) -> int:
    entry = get_pubkey(args.cipher)
    if args.cipher == "rsa":
        n, d = (int(v) for v in args.privkey.split(":"))
        priv = (n, d)
    elif args.cipher == "sm2":
        priv = int(args.privkey)
    else:  # elgamal
        p, g, x, q = (int(v) for v in args.privkey.split(":"))
        priv = ELGAMAL.ElGamalKey(p, g, x, q)
    plain = entry["decrypt"](bytes.fromhex(args.ct), priv)
    emit({"plaintext": plain.decode("utf-8", errors="replace")})
    return 0


# ---------------------------------------------------------------------------
# 数字签名（SM2-DSA）
# ---------------------------------------------------------------------------

def _sm2_point(pub_str: str):
    x, y = (int(v) for v in pub_str.split(":"))
    return x, y


def cmd_sign(args) -> int:
    if args.cipher != "sm2":
        return fail("签名暂仅支持 sm2（SM2-DSA）")
    d = int(args.privkey)
    pub = _sm2_point(args.pubkey)
    r, s = SM2.sign(args.text.encode("utf-8"), d, pub)
    emit({"cipher": "sm2", "signature": f"{r}:{s}"})
    return 0


def cmd_verify(args) -> int:
    if args.cipher != "sm2":
        return fail("验签暂仅支持 sm2（SM2-DSA）")
    pub = _sm2_point(args.pubkey)
    r, s = (int(v) for v in args.sig.split(":"))
    ok = SM2.verify(args.text.encode("utf-8"), (r, s), pub)
    emit({"valid": ok})
    return 0


# ---------------------------------------------------------------------------
# 散列 / HMAC
# ---------------------------------------------------------------------------

def cmd_hash(args) -> int:
    data = args.text.encode("utf-8")
    digest = md5_hex(data) if args.algo == "md5" else SM2.sm3(data).hex()
    emit({"algo": args.algo, "digest": digest})
    return 0


def cmd_hmac(args) -> int:
    mac = hmac_mod.new(args.key.encode("utf-8"), args.text.encode("utf-8"), hashlib.sha256).hexdigest()
    emit({"mac": mac})
    return 0


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent_cli.py", description="密码原语 CLI（供 agent 调用）")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("make_key", help="生成对称密码密钥")
    sp.add_argument("--cipher", required=True, choices=SYM_CIPHERS)
    sp.add_argument("--seed", help="可选：由种子派生密钥（缺省随机；pbkdf2 下作为口令必填）")
    sp.add_argument("--kdf", choices=["sha256", "pbkdf2"], default="sha256",
                    help="口令派生方式（pbkdf2 = 加盐 PBKDF2-HMAC-SHA256，防彩虹表）")
    sp.add_argument("--iterations", type=int, default=100000,
                    help="PBKDF2 迭代次数（默认 100000）")
    sp.add_argument("--salt", help="PBKDF2 的盐（hex；解密时传入以复现同一密钥，缺省随机生成）")
    sp.set_defaults(fn=cmd_make_key)

    sp = sub.add_parser("sym_encrypt", help="对称加密")
    sp.add_argument("--cipher", required=True, choices=SYM_CIPHERS)
    sp.add_argument("--text", required=True)
    sp.add_argument("--key", help="密钥（hex 或关键词），缺省自动生成")
    sp.set_defaults(fn=cmd_sym_encrypt)

    sp = sub.add_parser("sym_decrypt", help="对称解密")
    sp.add_argument("--cipher", required=True, choices=SYM_CIPHERS)
    sp.add_argument("--ct", required=True, help="密文 hex")
    sp.add_argument("--key", required=True, help="密钥（hex 或关键词）")
    sp.set_defaults(fn=cmd_sym_decrypt)

    sp = sub.add_parser("pubkey_keygen", help="生成公钥密钥对")
    sp.add_argument("--cipher", required=True, choices=PUBKEY_CIPHERS)
    sp.set_defaults(fn=cmd_pubkey_keygen)

    sp = sub.add_parser("pubkey_encrypt", help="公钥加密")
    sp.add_argument("--cipher", required=True, choices=PUBKEY_CIPHERS)
    sp.add_argument("--text", required=True)
    sp.add_argument("--pubkey", required=True)
    sp.set_defaults(fn=cmd_pubkey_encrypt)

    sp = sub.add_parser("pubkey_decrypt", help="私钥解密")
    sp.add_argument("--cipher", required=True, choices=PUBKEY_CIPHERS)
    sp.add_argument("--ct", required=True, help="密文 hex")
    sp.add_argument("--privkey", required=True)
    sp.set_defaults(fn=cmd_pubkey_decrypt)

    sp = sub.add_parser("sign", help="数字签名（SM2-DSA）")
    sp.add_argument("--cipher", required=True, choices=SIGN_CIPHERS)
    sp.add_argument("--text", required=True, help="要签名的消息")
    sp.add_argument("--privkey", required=True)
    sp.add_argument("--pubkey", required=True, help="SM2 签名需同时提供公钥（ZA 预处理）")
    sp.set_defaults(fn=cmd_sign)

    sp = sub.add_parser("verify", help="验签（SM2-DSA）")
    sp.add_argument("--cipher", required=True, choices=SIGN_CIPHERS)
    sp.add_argument("--text", required=True, help="原始消息")
    sp.add_argument("--sig", required=True, help="签名 r:s")
    sp.add_argument("--pubkey", required=True)
    sp.set_defaults(fn=cmd_verify)

    sp = sub.add_parser("hash", help="散列")
    sp.add_argument("--algo", required=True, choices=HASH_ALGOS)
    sp.add_argument("--text", required=True)
    sp.set_defaults(fn=cmd_hash)

    sp = sub.add_parser("hmac", help="HMAC-SHA256 完整性校验")
    sp.add_argument("--text", required=True)
    sp.add_argument("--key", required=True)
    sp.set_defaults(fn=cmd_hmac)

    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.fn(args)
    except Exception as exc:  # noqa: BLE001 —— 原语失败统一转 JSON 错误
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
