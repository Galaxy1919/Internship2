#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ElGamal 公钥密码从零实现
=========================

原理
----
ElGamal(Taher ElGamal, 1985)的安全性依赖"离散对数问题"(DLP):
已知 g、y = g^x mod p,求 x 极其困难(当 p 为大安全素数时)。

密钥生成
    选安全素数 p = 2q + 1(q 也是素数),生成元 g
    私钥 x ∈ [2, q - 1]
    公钥 y = g^x mod p
    公开: (p, g, y);保密: x

加密 (公钥 y 加密明文 m ∈ [1, p-1])
    随机会话密钥 k ∈ [2, q-1]  (每次必须新鲜!)
    c1 = g^k mod p
    c2 = m · y^k mod p
    密文 = (c1, c2)

解密 (私钥 x)
    m = c2 · (c1^x)^{-1} mod p
      = c2 · c1^{p-1-x} mod p    (费马小定理避免求逆)

签名 (Schnorr 变体; 这里用经典 ElGamal 签名)
    选临时秘密 k ∈ [2, p-2], gcd(k, p-1) = 1
    r = g^k mod p
    s = (H(m) - x·r) · k^{-1} mod (p - 1)
    签名 = (r, s)

验证
    要求 0 < r < p 且 g^{H(m)} ≡ y^r · r^s (mod p)

创新点
------
1. **安全素数生成**:课堂上常见的 ElGamal 教学实现直接找质数,但如果
   p-1 只有小因子,DLP 会退化。本实现明确生成 p = 2q + 1 且 q 也是素数,
   并选阶为 q 的生成元 g。
2. **k 重用攻击演示**:如果两次签名用了同一个 k,私钥 x 会被直接恢复。
   程序演示这一攻击,警示 nonce 必须真随机。
3. **对比 ElGamal vs RSA**:同长度密钥下签名/密文更长,但天然抗"密文
   同态复制"(每次密文都不同),课堂对比一目了然。

注意
----
本实现只做数学核心,没有对消息做 hash-then-encrypt 或标准 padding,
仅作教学。加密的明文必须小于 p。

运行方式
--------
    python main.py --selftest
    python main.py --demo
"""
from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from math import gcd
from typing import Tuple


# ---------------------------------------------------------------------------
# 素数与生成元
# ---------------------------------------------------------------------------

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def miller_rabin(n: int, k: int = 20) -> bool:
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    r, d = 0, n - 1
    while d & 1 == 0:
        d >>= 1
        r += 1
    for _ in range(k):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        composite = True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def gen_safe_prime(bits: int) -> Tuple[int, int]:
    """生成安全素数对 (p, q):p = 2q + 1,且 p、q 都是素数。

    生产上常用 2048/3072 bit;这里默认 256 bit 让课堂能几秒内跑完。
    """
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if not miller_rabin(q):
            continue
        p = 2 * q + 1
        if miller_rabin(p):
            return p, q


def find_generator(p: int, q: int) -> int:
    """找 Zp* 中阶为 q 的元素 g,即在 q 阶子群里。

    p = 2q + 1 时,Zp* 阶为 2q,子群阶只能是 {1, 2, q, 2q}。
    随便取 h,g = h^{(p-1)/q} = h^2。若 g != 1 则 g 的阶必为 q。
    """
    while True:
        h = 2 + secrets.randbelow(p - 3)
        g = pow(h, 2, p)
        if g != 1:
            return g


# ---------------------------------------------------------------------------
# 密钥对
# ---------------------------------------------------------------------------

class ElGamalKey:
    """ElGamal 密钥对。公钥 (p, g, y),私钥 x。"""

    def __init__(self, p: int, g: int, x: int, q: int):
        self.p = p
        self.g = g
        self.x = x
        self.q = q
        self.y = pow(g, x, p)

    @property
    def public(self) -> Tuple[int, int, int]:
        return (self.p, self.g, self.y)


def generate_key(bits: int = 256) -> ElGamalKey:
    p, q = gen_safe_prime(bits)
    g = find_generator(p, q)
    x = 2 + secrets.randbelow(q - 3)
    return ElGamalKey(p, g, x, q)


# ---------------------------------------------------------------------------
# 加解密
# ---------------------------------------------------------------------------

def encrypt(m: int, pub: Tuple[int, int, int], k: int | None = None) -> Tuple[int, int]:
    """加密返回 (c1, c2)。k 可选,仅在测试或攻击演示时手动指定。"""
    p, g, y = pub
    if not (1 <= m < p):
        raise ValueError(f"明文 m 必须 1 ≤ m < p,当前 m={m}, p bits={p.bit_length()}")
    if k is None:
        k = 2 + secrets.randbelow(p - 3)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


def decrypt(ct: Tuple[int, int], key: ElGamalKey) -> int:
    """解密 m = c2 · c1^{-x} mod p,用费马小定理避免求逆。"""
    c1, c2 = ct
    # c1^{-x} ≡ c1^{p-1-x} (mod p),因为 c1^{p-1} ≡ 1
    inv = pow(c1, key.p - 1 - key.x, key.p)
    return (c2 * inv) % key.p


# ---------------------------------------------------------------------------
# 签名与验证
# ---------------------------------------------------------------------------

def _h(msg: bytes, p: int) -> int:
    """把消息哈希到 [0, p-1]。"""
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % p


def modinv(a: int, m: int) -> int:
    g, s, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} 在模 {m} 下无逆")
    return s % m


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def sign(msg: bytes, key: ElGamalKey, k: int | None = None) -> Tuple[int, int]:
    """ElGamal 签名 (r, s)。k 可选,便于攻击演示。"""
    p = key.p
    while True:
        if k is None:
            k_try = 2 + secrets.randbelow(p - 3)
        else:
            k_try = k
        if gcd(k_try, p - 1) != 1:
            if k is not None:
                raise ValueError("指定的 k 与 p-1 不互素,不能用于签名")
            continue
        r = pow(key.g, k_try, p)
        h = _h(msg, p)
        s = (modinv(k_try, p - 1) * (h - key.x * r)) % (p - 1)
        if s == 0:
            if k is not None:
                raise ValueError("指定的 k 导致 s=0,请换一个 k")
            continue
        return r, s


def verify(msg: bytes, sig: Tuple[int, int], pub: Tuple[int, int, int]) -> bool:
    p, g, y = pub
    r, s = sig
    if not (0 < r < p and 0 < s < p - 1):
        return False
    h = _h(msg, p)
    lhs = pow(g, h, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    return lhs == rhs


# ---------------------------------------------------------------------------
# 创新点:k 重用攻击
# ---------------------------------------------------------------------------

def recover_x_from_reused_k(
    msg1: bytes,
    sig1: Tuple[int, int],
    msg2: bytes,
    sig2: Tuple[int, int],
    pub: Tuple[int, int, int],
) -> int:
    """若两次签名共用了同一个 k,则:

        s1 = (h1 - x·r) / k
        s2 = (h2 - x·r) / k        (r 相同,因为 r = g^k mod p)
    =>  k = (h1 - h2) / (s1 - s2)  mod (p - 1)
    =>  x = (h1 - k·s1) / r        mod (p - 1)

    因此攻击者只需两个复用同一 k 的签名,即可恢复私钥 x。
    """
    p, g, _ = pub
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("两次签名的 r 不同,说明 k 未复用;此攻击不适用")
    h1 = _h(msg1, p)
    h2 = _h(msg2, p)
    k = ((h1 - h2) * modinv((s1 - s2) % (p - 1), p - 1)) % (p - 1)
    x = ((h1 - k * s1) * modinv(r1, p - 1)) % (p - 1)
    return x


# ---------------------------------------------------------------------------
# 自检与演示
# ---------------------------------------------------------------------------

def selftest() -> bool:
    ok = True

    # 1. 安全素数结构
    p, q = gen_safe_prime(64)
    struct_ok = (p == 2 * q + 1) and miller_rabin(p) and miller_rabin(q)
    print(f"  [{'PASS' if struct_ok else 'FAIL'}] 安全素数 p=2q+1 结构正确 (p bits={p.bit_length()})")
    ok = ok and struct_ok

    # 2. 生成元阶为 q
    g = find_generator(p, q)
    g_ok = pow(g, q, p) == 1 and g != 1
    print(f"  [{'PASS' if g_ok else 'FAIL'}] 生成元 g 的阶为 q  (g^q mod p == 1)")
    ok = ok and g_ok

    # 3. 加解密往返
    key = generate_key(bits=128)
    m = 0xCAFEBABE
    ct = encrypt(m, key.public)
    back = decrypt(ct, key)
    rt_ok = back == m
    print(f"  [{'PASS' if rt_ok else 'FAIL'}] 加解密往返: {hex(m)} -> {hex(back)}")
    ok = ok and rt_ok

    # 4. 每次密文不同(随机 k)
    ct2 = encrypt(m, key.public)
    fresh_ok = ct != ct2 and decrypt(ct2, key) == m
    print(f"  [{'PASS' if fresh_ok else 'FAIL'}] 同一明文两次加密密文不同 (随机 k)")
    ok = ok and fresh_ok

    # 5. 签名与验证
    msg = "ElGamal 签名 test".encode("utf-8")
    sig = sign(msg, key)
    v1 = verify(msg, sig, key.public)
    v2 = verify(msg + b"?", sig, key.public)
    sig_ok = v1 and (not v2)
    print(f"  [{'PASS' if sig_ok else 'FAIL'}] 签名验证: 原消息={v1}, 篡改={not v2}")
    ok = ok and sig_ok

    # 6. k 重用攻击可恢复私钥
    msg1 = b"transfer 100 to Alice"
    msg2 = b"transfer 100 to Bob"
    k = 2 + secrets.randbelow(key.p - 3)
    while gcd(k, key.p - 1) != 1:
        k = 2 + secrets.randbelow(key.p - 3)
    s1 = sign(msg1, key, k=k)
    s2 = sign(msg2, key, k=k)
    x_recovered = recover_x_from_reused_k(msg1, s1, msg2, s2, key.public)
    attack_ok = x_recovered == key.x
    print(f"  [{'PASS' if attack_ok else 'FAIL'}] k 重用攻击成功恢复私钥 x")
    ok = ok and attack_ok

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


def demo() -> None:
    print("=" * 60)
    print("ElGamal 完整演示")
    print("=" * 60)

    print("1) 生成 256-bit 安全素数密钥对...")
    key = generate_key(bits=256)
    print(f"   p (bits={key.p.bit_length()}) = {hex(key.p)[:34]}...")
    print(f"   g = {key.g}")
    print(f"   x (私) = {hex(key.x)[:34]}...")
    print(f"   y (公) = {hex(key.y)[:34]}...")

    print()
    print("2) 加解密")
    m = 0x12345678
    ct1 = encrypt(m, key.public)
    ct2 = encrypt(m, key.public)
    print(f"   明文 m = {hex(m)}")
    print(f"   第 1 次密文 (c1, c2) 前 hex: ({hex(ct1[0])[:20]}..., {hex(ct1[1])[:20]}...)")
    print(f"   第 2 次密文 (c1, c2) 前 hex: ({hex(ct2[0])[:20]}..., {hex(ct2[1])[:20]}...)")
    print(f"   两次不同? {ct1 != ct2}  (创新点: ElGamal 天然抗密文重放对比)")
    print(f"   解密还原: {hex(decrypt(ct1, key))}")

    print()
    print("3) 签名验证")
    msg = "ElGamal demo message".encode("utf-8")
    sig = sign(msg, key)
    print(f"   消息    : {msg.decode('utf-8')}")
    print(f"   (r, s) 前 hex: ({hex(sig[0])[:20]}..., {hex(sig[1])[:20]}...)")
    print(f"   验证    : {verify(msg, sig, key.public)}")

    print()
    print("4) 创新点: k 重用攻击演示")
    print("   Alice 两次签名用了同一个 k(严重实现错误)...")
    while True:
        k = 2 + secrets.randbelow(key.p - 3)
        if gcd(k, key.p - 1) == 1:
            break
    m1 = b"pay 100 to bank A"
    m2 = b"pay 999 to bank Z"
    s1 = sign(m1, key, k=k)
    s2 = sign(m2, key, k=k)
    print(f"   sig1 = ({hex(s1[0])[:16]}..., ...)")
    print(f"   sig2 = ({hex(s2[0])[:16]}..., ...)  -- r 相同,已泄露!")
    x = recover_x_from_reused_k(m1, s1, m2, s2, key.public)
    print(f"   攻击者算得 x = {hex(x)[:34]}...")
    print(f"   与真实私钥一致? {x == key.x}  (证明 nonce 必须真随机)")


def main() -> int:
    ap = argparse.ArgumentParser(description="ElGamal 从零实现")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if not (args.selftest or args.demo):
        selftest()
        print()
        demo()
        return 0
    if args.selftest and not selftest():
        return 1
    if args.demo:
        demo()
    return 0


if __name__ == "__main__":
    sys.exit(main())
