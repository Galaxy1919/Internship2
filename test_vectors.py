#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""标准测试向量：用 NIST / GM/T 官方向量验证 AES / DES / SM3 实现的正确性。

自测只能证明「自洽」（加解密互为逆），官方向量才能证明「与标准一致」。
本脚本把三套实现分别对拍官方测试向量，作为算法正确性的客观证据。

用法：python3 test_vectors.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DH = ROOT / "DH"
if str(DH) not in sys.path:
    sys.path.insert(0, str(DH))

from cipher_registry import AES, DES, SM2  # noqa: E402


def check(name, got_hex, want_hex):
    ok = got_hex.upper() == want_hex.upper()
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"        实际 {got_hex.upper()}")
        print(f"        期望 {want_hex.upper()}")
    return ok


def test_aes():
    """FIPS-197 Appendix C.1（AES-128 官方向量）。"""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = "69c4e0d86a7b0430d8cdb78070b4c55a"
    ct = AES.encrypt_block(pt, key)
    ok1 = check("AES-128 加密 (FIPS-197)", ct.hex(), want)
    ok2 = check("AES-128 解密", AES.decrypt_block(ct, key).hex(), pt.hex())
    return ok1 and ok2


def test_des():
    """FIPS 46-3 / NIST SP 800-67 标准向量。"""
    key = bytes.fromhex("133457799BBCDFF1")
    pt = bytes.fromhex("0123456789ABCDEF")
    want = "85E813540F0AB405"
    ct = DES.block(pt, key)
    ok1 = check("DES 加密 (FIPS 46-3)", ct.hex(), want)
    ok2 = check("DES 解密", DES.block(ct, key, dec=True).hex(), pt.hex())
    return ok1 and ok2


def test_sm3():
    """GM/T 0004-2012 附录 A（SM3 官方向量）。"""
    vectors = [
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"abcd" * 16,
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
    ]
    ok = True
    for msg, want in vectors:
        label = msg.decode("ascii") if len(msg) <= 8 else msg[:8].decode("ascii") + "...(64B)"
        ok = check(f"SM3({label}) (GM/T 0004-2012)", SM2.sm3(msg).hex(), want) and ok
    return ok


if __name__ == "__main__":
    print("AES 官方向量：")
    a = test_aes()
    print("DES 官方向量：")
    d = test_des()
    print("SM3 官方向量：")
    s = test_sm3()
    print("全部通过 ✓" if (a and d and s) else "存在失败 ✗")
    sys.exit(0 if (a and d and s) else 1)
