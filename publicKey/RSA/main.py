#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSA 公钥密码从零实现
=====================

原理
----
RSA(Rivest-Shamir-Adleman, 1977)的安全性建立在"大整数分解困难"上。

1. 密钥生成
   随机选两个大素数 p、q,计算:
       n = p · q                (公开的模数)
       φ(n) = (p - 1)(q - 1)    (欧拉函数,保密)
       选 e 使 gcd(e, φ(n)) = 1,通常取 65537(0x10001)
       d = e^{-1} mod φ(n)      (私钥)
   公钥 = (n, e);私钥 = (n, d)。

2. 加解密
       c = m^e mod n
       m = c^d mod n
   两次幂运算互为逆运算,根据欧拉定理:m^{φ(n)} ≡ 1 (mod n)。

3. 签名 / 验证
       s = H(m)^d mod n           (用私钥签)
       verify: s^e mod n == H(m)  (用公钥验)

创新点
------
1. **Miller-Rabin 概率素性检测**:课堂上直接看到"通过 k 轮独立见证"
   的过程,而不是黑箱调用 sympy.isprime。
2. **CRT 加速解密**:利用中国剩余定理把 c^d mod n 拆成两次小模幂,
   实际加速 ~4x。程序同时给出普通与 CRT 两条路径,对比结果一致。
3. **"小 e + 短明文"攻击演示**:e=3、明文很小(m^3 < n)时,直接对
   密文开立方即可恢复,不需要私钥。教学用,警示实践中必须做填充。

注意
----
本实现只做 RSA 数学核心,**没有 OAEP / PSS 填充**,不能直接用于生产。
仅作课程演示。加密的明文必须小于 n。

运行方式
--------
    python main.py --selftest      # 自检
    python main.py --demo          # 完整演示(密钥生成 + 加密 + 签名 + 攻击)
"""
from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from math import gcd
from typing import Tuple, List


# ---------------------------------------------------------------------------
# 素数生成:Miller-Rabin 概率素性检测
# ---------------------------------------------------------------------------

# 小素数试除表:先滤掉明显合数,大幅加速
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def miller_rabin(n: int, k: int = 20, trace: List[str] | None = None) -> bool:
    """Miller-Rabin 概率素性检测,做 k 轮独立见证。

    n < 2 或偶数直接判定;否则把 n-1 写成 d·2^r,随机取 a,验证:
        a^d ≡ 1 (mod n)     或
        a^{d·2^i} ≡ -1 (mod n) 对某个 0 ≤ i < r 成立
    任一见证失败即判定为合数。误判概率 ≤ 4^{-k}。
    """
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # 把 n - 1 拆成 d · 2^r,d 为奇数
    r, d = 0, n - 1
    while d & 1 == 0:
        d >>= 1
        r += 1

    for i in range(k):
        a = 2 + secrets.randbelow(n - 3)         # a ∈ [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            if trace is not None:
                trace.append(f"  轮 {i+1}: a={a} 见证 -> 首步即通过")
            continue
        composite = True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            if trace is not None:
                trace.append(f"  轮 {i+1}: a={a} 见证 n 是合数,返回 False")
            return False
        if trace is not None:
            trace.append(f"  轮 {i+1}: a={a} 见证通过")
    return True


def gen_prime(bits: int, rng=secrets) -> int:
    """生成一个指定比特长度的概率素数,最高位、最低位强制为 1。"""
    if bits < 8:
        raise ValueError("素数比特长度至少 8")
    while True:
        # randbits(bits) 高位可能是 0;显式置最高、最低位保证长度和奇性
        candidate = rng.randbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(candidate):
            return candidate


# ---------------------------------------------------------------------------
# 有限域运算
# ---------------------------------------------------------------------------

def modinv(a: int, m: int) -> int:
    """扩展欧几里得算法求 a 在模 m 下的乘法逆元。

    Python 3.8+ 的 pow(a, -1, m) 也是同样效果;这里手写一遍是为了
    在课堂上让学生看到 (r0, s0, t0) -> (r1, s1, t1) 的每一步。
    """
    r0, r1, s0, s1 = a % m, m, 1, 0
    while r1:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
    if r0 != 1:
        raise ValueError(f"{a} 在模 {m} 下无乘法逆元")
    return s0 % m


# ---------------------------------------------------------------------------
# RSA 密钥对与加解密
# ---------------------------------------------------------------------------

class RSAKey:
    """RSA 密钥对容器,保存公钥 (n, e) 与私钥 (n, d),外加 p、q 用于 CRT。"""

    def __init__(self, n: int, e: int, d: int, p: int, q: int):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        # 预计算 CRT 加速用参数
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)
        self.qinv = modinv(q, p)

    @property
    def public(self) -> Tuple[int, int]:
        return (self.n, self.e)

    @property
    def private(self) -> Tuple[int, int]:
        return (self.n, self.d)


def generate_key(bits: int = 512, e: int = 65537) -> RSAKey:
    """生成一个 bits 长的 RSA 密钥对(两个约 bits/2 长的素数)。

    保证 p ≠ q,且 gcd(e, φ(n)) == 1。生产上 bits ≥ 2048;这里默认 512
    是为了课堂能在几秒内跑完;bits=1024 也很快。
    """
    if bits < 32:
        raise ValueError("bits 太小,无法承载 e=65537")
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break
    n = p * q
    d = modinv(e, phi)
    return RSAKey(n, e, d, p, q)


def encrypt(m: int, pub: Tuple[int, int]) -> int:
    """裸 RSA 加密:c = m^e mod n。要求 0 ≤ m < n。"""
    n, e = pub
    if not (0 <= m < n):
        raise ValueError(f"明文 m 必须满足 0 ≤ m < n,当前 m={m}, n bits={n.bit_length()}")
    return pow(m, e, n)


def decrypt(c: int, priv: Tuple[int, int]) -> int:
    """裸 RSA 解密:m = c^d mod n(直接模幂,不用 CRT)。"""
    n, d = priv
    return pow(c, d, n)


def decrypt_crt(c: int, key: RSAKey) -> int:
    """CRT 加速版解密。

    m1 = c^dp mod p
    m2 = c^dq mod q
    h  = (qinv · (m1 - m2)) mod p
    m  = m2 + h · q
    """
    m1 = pow(c, key.dp, key.p)
    m2 = pow(c, key.dq, key.q)
    h = (key.qinv * (m1 - m2)) % key.p
    return m2 + h * key.q


# ---------------------------------------------------------------------------
# 签名与验证 (仍是裸 RSA + SHA-256, 无 PSS 填充,仅教学)
# ---------------------------------------------------------------------------

def _hash_to_int(message: bytes, n: int) -> int:
    """把消息哈希后截取到 < n,用作签名的输入整数。"""
    h = hashlib.sha256(message).digest()
    # SHA-256 是 32 字节;若 n 太小则截取,若 n 大则直接用即可
    max_bytes = (n.bit_length() - 1) // 8
    if max_bytes < len(h):
        h = h[:max_bytes]
    return int.from_bytes(h, "big") % n


def sign(message: bytes, key: RSAKey) -> int:
    return pow(_hash_to_int(message, key.n), key.d, key.n)


def verify(message: bytes, signature: int, pub: Tuple[int, int]) -> bool:
    n, e = pub
    return pow(signature, e, n) == _hash_to_int(message, n)


# ---------------------------------------------------------------------------
# 创新点:低 e 立方根攻击(演示"裸 RSA + 小明文"不安全)
# ---------------------------------------------------------------------------

def integer_cube_root(x: int) -> int:
    """整数立方根,牛顿迭代求。"""
    if x < 0:
        raise ValueError("要求非负整数")
    if x < 2:
        return x
    # 初值
    r = 1 << ((x.bit_length() + 2) // 3)
    while True:
        nr = (2 * r + x // (r * r)) // 3
        if nr >= r:
            return r
        r = nr


def low_exponent_attack(c: int, e: int = 3) -> int:
    """当 e = 3 且 m^3 < n 时,c = m^3 in Z,直接开立方即可恢复 m,无需私钥。"""
    if e != 3:
        raise NotImplementedError("此教学攻击仅演示 e=3 的情形")
    m = integer_cube_root(c)
    if m ** 3 != c:
        raise ValueError("立方根不是整数,说明 m^3 ≥ n,该攻击不适用")
    return m


# ---------------------------------------------------------------------------
# 自检与演示
# ---------------------------------------------------------------------------

# 用于确定性自检的固定小参数(FIPS 教材经典)
FIXED_P = 61
FIXED_Q = 53
# n = 3233, phi = 3120, e = 17, d = 2753


def selftest() -> bool:
    ok = True

    # 1. 固定小参数:课本例子 p=61 q=53 e=17
    p, q, e = FIXED_P, FIXED_Q, 17
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    d_ok = d == 2753 and n == 3233
    print(f"  [{'PASS' if d_ok else 'FAIL'}] 教材例 p=61 q=53 e=17: n={n}(期望 3233), d={d}(期望 2753)")
    ok = ok and d_ok

    # 2. 加解密往返
    m = 123
    c = pow(m, e, n)
    back = pow(c, d, n)
    rt_ok = back == m
    print(f"  [{'PASS' if rt_ok else 'FAIL'}] 教材例加解密往返: m={m} -> c={c} -> m={back}")
    ok = ok and rt_ok

    # 3. Miller-Rabin 对已知合数/素数正确判定
    mr1 = miller_rabin(561)          # Carmichael 数,合数
    mr2 = miller_rabin(2 ** 127 - 1) # Mersenne 素数 M127
    mr_ok = (mr1 is False) and (mr2 is True)
    print(f"  [{'PASS' if mr_ok else 'FAIL'}] Miller-Rabin: 561 合数={not mr1}, M127 素数={mr2}")
    ok = ok and mr_ok

    # 4. 真实规模:512-bit 密钥 + CRT 加速一致性
    key = generate_key(bits=512)
    plain = 0xDEADBEEFCAFEBABE
    c = encrypt(plain, key.public)
    m1 = decrypt(c, key.private)
    m2 = decrypt_crt(c, key)
    crt_ok = m1 == plain and m2 == plain
    print(f"  [{'PASS' if crt_ok else 'FAIL'}] 512-bit 密钥加解密 + CRT 一致")
    ok = ok and crt_ok

    # 5. 签名验证
    msg = "RSA 签名测试 message".encode("utf-8")
    sig = sign(msg, key)
    v1 = verify(msg, sig, key.public)
    v2 = verify(msg + b"tampered", sig, key.public)
    sig_ok = v1 and (not v2)
    print(f"  [{'PASS' if sig_ok else 'FAIL'}] 签名: 正确消息通过={v1}, 篡改消息拒绝={not v2}")
    ok = ok and sig_ok

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


def demo() -> None:
    print("=" * 60)
    print("RSA 完整演示")
    print("=" * 60)

    print("1) 生成 512-bit 密钥对(概率素数,请稍候)...")
    key = generate_key(bits=512)
    print(f"   n = {hex(key.n)}")
    print(f"   e = {key.e}")
    print(f"   d(私,示例前 32 hex) = {hex(key.d)[:34]}...")
    print(f"   p = {hex(key.p)[:34]}...")
    print(f"   q = {hex(key.q)[:34]}...")

    print()
    print("2) 加解密")
    plain = 0x1234567890ABCDEF
    c = encrypt(plain, key.public)
    print(f"   明文  m = {hex(plain)}")
    print(f"   密文  c = {hex(c)[:50]}...")
    m1 = decrypt(c, key.private)
    m2 = decrypt_crt(c, key)
    print(f"   普通解密  = {hex(m1)}")
    print(f"   CRT 解密  = {hex(m2)}  (创新点: 与普通解密一致 {'✓' if m1 == m2 else '✗'})")

    print()
    print("3) 签名与验证")
    msg = "hello RSA 签名 2026".encode("utf-8")
    sig = sign(msg, key)
    print(f"   消息 : {msg.decode('utf-8')}")
    print(f"   签名 : {hex(sig)[:50]}...")
    print(f"   原消息验证:  {verify(msg, sig, key.public)}")
    print(f"   篡改消息验证: {verify(msg + b'!', sig, key.public)}(应为 False)")

    print()
    print("4) 创新点: 低 e 立方根攻击(e=3, 小明文, 无填充)")
    weak = generate_key(bits=512, e=3)
    small_m = 42
    weak_c = encrypt(small_m, weak.public)
    recovered = low_exponent_attack(weak_c, e=3)
    print(f"   明文 m={small_m}, 密文 c={weak_c}")
    print(f"   直接对 c 开立方 -> m={recovered}  (无需私钥即可恢复,证明必须做填充)")


def main() -> int:
    ap = argparse.ArgumentParser(description="RSA 从零实现")
    ap.add_argument("--selftest", action="store_true", help="运行自检")
    ap.add_argument("--demo", action="store_true", help="完整演示")
    ap.add_argument("--bits", type=int, default=512, help="密钥比特长度(默认 512)")
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
