#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2

创新点
仿照 ECC 教学模块,给出公钥四项校验(在曲线上、非无穷远、坐标在 [0, p)、n·PubKey = O),防小子群/无效曲线攻击。

运行
python main.py --selftest
python main.py --demo
"""
from __future__ import annotations

import argparse
import secrets
import sys
import struct
from dataclasses import dataclass
from typing import Optional, Tuple, List

# 一、SM3 摘要函数(GM/T 0004-2012)

_IV = (0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
       0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)


def _rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _P0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _P1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _ff(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(j: int, x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x) & 0xFFFFFFFF & z))


def sm3(message: bytes) -> bytes:
    """SM3(m):返回 32 字节摘要。"""
    # 填充:0x80,补 0 至 mod 64 == 56,末尾 8 字节大端位长度
    bit_len = len(message) * 8
    msg = bytearray(message)
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += struct.pack(">Q", bit_len)

    V = list(_IV)
    for off in range(0, len(msg), 64):# 每64字节为一块，拆分原文msg
        W = list(struct.unpack(">16I", msg[off:off + 64])) #每个64字节的块拆成16个32进制的大端字W[0...15]
        for i in range(16, 68):# 64字节扩展为68字节
            W.append(_P1(W[i - 16] ^ W[i - 9] ^ _rotl(W[i - 3], 15))
                     ^ _rotl(W[i - 13], 7) ^ W[i - 6])
        W_ = [(W[i] ^ W[i + 4]) & 0xFFFFFFFF for i in range(64)]# W_[i]=W[i]⊕W[i+4]，W_共64个元素

        A, B, C, D, E, F, G, H = V
        for j in range(64):
            T = 0x79CC4519 if j < 16 else 0x7A879D8A
            SS1 = _rotl(((_rotl(A, 12) + E + _rotl(T, j)) & 0xFFFFFFFF), 7)
            SS2 = SS1 ^ _rotl(A, 12)
            TT1 = (_ff(j, A, B, C) + D + SS2 + W_[j]) & 0xFFFFFFFF
            TT2 = (_gg(j, E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = _rotl(B, 9)
            B = A
            A = TT1
            H = G
            G = _rotl(F, 19)
            F = E
            E = _P0(TT2)

        V = [(v ^ nv) & 0xFFFFFFFF for v, nv in zip(V, (A, B, C, D, E, F, G, H))]

    return struct.pack(">8I", *V)

# 二、SM2 曲线参数(GM/T 0003.5-2012 推荐参数)

# 密文C=C1||C3||C2
# C1=k*G,k∈[1,n-1]随机数
# C3=Hash(x2||M||y2)，其中(x2,y2)=k*pub,pub=d*G，d∈[1，n-1]随机，d作为私钥
# C2=M⊕t,t=KDF(x2||y2,klen)
# KDF(Z,klen):输入比特串Z，输出长度位klen的比特串K
# 初始化32bit计数器ct=0x00000001,计算Hai=Hv(Z||ct++),Hv()这里为SM3,v代表Hv输出的长度
# 由此循环ceiling(klen/v)次，最后一次可能有截断，由此得到的所有Ha拼接得到K=Ha1||Ha2||...

Point = Optional[Tuple[int, int]]# Point=(x,y) or None(无穷远点)


@dataclass(frozen=True)
class SM2Curve:
    p: int
    a: int
    b: int
    Gx: int
    Gy: int
    n: int

    @property
    def G(self) -> Point:
        return (self.Gx, self.Gy)


SM2 = SM2Curve(
    p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
    n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
)# GM/T 0003.5标准参数

# 三、椭圆曲线相关
def _modinv(x: int, p: int) -> int:# 模逆运算
    return pow(x, -1, p)


# 优化一: SM2 曲线参数特化的快速模约减
# SM2 推荐素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1 是广义梅森素数,
# 由此可推出:  2^256 ≡ 2^224 + 2^96 - 2^64 + 1   (mod p)
# 用这条同余式把中间值(最多 512 位)的高 256 位反复"折叠"到低位,
# 最后只需少量条件减法即可落到 [0, p),规避一次大整数长除法(即通用的 x % p)。

_MASK256 = (1 << 256) - 1

def _fast_mod_p(x: int, C: SM2Curve = SM2) -> int:
    """基于 SM2 素数结构的快速模约减,等价于 x % C.p 但走的是加/减/移位。"""
    p = C.p
    # 负数不是主路径(减法可能出现),回退到内建即可
    if x < 0:
        return x % p
    # 高位折叠:每轮把最高的 H 项打散成 (H<<224)+(H<<96)-(H<<64)+H,
    # 由于 2^224 > 2^64,单轮结果保持非负;每轮最高位收缩 ~32 位,
    # 从最坏 512 位收敛到 256 位以内只需约 8 轮
    while x > _MASK256:
        H = x >> 256
        L = x & _MASK256
        x = L + (H << 224) + (H << 96) - (H << 64) + H
    # 尾部:此时 x 已在 [0, 2*p) 附近,最多几次减法就能落进 [0, p)
    while x >= p:
        x -= p
    return x


def is_on_curve(P: Point, C: SM2Curve = SM2) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + C.a * x + C.b)) % C.p == 0

def point_add(P: Point, Q: Point, C: SM2Curve = SM2) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % C.p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + C.a) * _modinv(2 * y1, C.p) % C.p
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, C.p) % C.p
    x3 = (lam * lam - x1 - x2) % C.p
    y3 = (lam * (x1 - x3) - y1) % C.p
    return (x3, y3)

def scalar_mul(k: int, P: Point, C: SM2Curve = SM2) -> Point:
    if k == 0 or P is None:
        return None
    if k < 0:
        x, y = P  # type: ignore
        return scalar_mul(-k, (x, (-y) % C.p), C)
    result: Point = None
    addend: Point = P
    while k > 0:
        if k & 1:
            result = point_add(result, addend, C)
        addend = point_add(addend, addend, C)
        k >>= 1
    return result

def public_key_is_valid(pub: Point, C: SM2Curve = SM2) -> bool:# 公钥合法性检查
    if pub is None:# 无穷远点不合法
        return False
    x, y = pub
    if not (0 <= x < C.p and 0 <= y < C.p):# 由于x,y是mod p下的，所以x、y必须<=p
        return False
    if not is_on_curve(pub, C):# 不在曲线上不合法
        return False
    return scalar_mul(C.n, pub, C) is None # n*Q!=O不合法，n作为G的阶，有n*G=O,Q=d*G,所以n*Q=n*G*d=O*d应当=O

# 四、密钥对与 ZA 预处理
def generate_keypair(C: SM2Curve = SM2) -> Tuple[int, Point]:
    d = 1 + secrets.randbelow(C.n - 1)# 生成密钥，d∈[1,n-1]
    return d, scalar_mul(d, C.G, C) # 公钥Q=scalar_mul(d, C.G, C)=d*G

def _int_to_bytes(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")

def compute_ZA(user_id: bytes, pub: Point, C: SM2Curve = SM2) -> bytes:
    """SM2-DSA 的 ZA 预处理:把用户 ID、曲线参数、公钥一起哈希,后续再和消息拼接。
    ZA = SM3( ENTL_A || ID_A || a || b || xG || yG || xA || yA )
      ENTL_A: ID_A 的比特长度(2 字节大端),其余为32字节大端
    """# 仅用于签名与验签
    if pub is None:
        raise ValueError("公钥不能是无穷远")
    entl = (len(user_id) * 8).to_bytes(2, "big")
    body = (
        entl + user_id
        + _int_to_bytes(C.a, 32)
        + _int_to_bytes(C.b, 32)
        + _int_to_bytes(C.Gx, 32)
        + _int_to_bytes(C.Gy, 32)
        + _int_to_bytes(pub[0], 32)
        + _int_to_bytes(pub[1], 32)
    )
    return sm3(body)

# 五、SM2 数字签名

DEFAULT_ID = b"1234567812345678"  # GM/T 0003.5 默认标识

def sign(msg: bytes, d: int, pub: Point, user_id: bytes = DEFAULT_ID,
         C: SM2Curve = SM2, k: int | None = None) -> Tuple[int, int]:
    """SM2 签名 (r, s)。k 可选,便于向量对齐/攻击演示。"""
    ZA = compute_ZA(user_id, pub, C)# ZA = SM3( ENTL_A || ID_A || a || b || xG || yG || xA || yA )
    e = int.from_bytes(sm3(ZA + msg), "big") # e=SM3(ZA||M)
    while True:
        k_try = k if k is not None else (1 + secrets.randbelow(C.n - 1))# 随机选取k
        P1 = scalar_mul(k_try, C.G, C)# P1=kG
        if P1 is None:
            if k is not None:
                raise ValueError("指定的 k 生成无穷远点")
            continue
        x1, _ = P1
        r = (e + x1) % C.n # r=(e+x1)%n
        if r == 0 or (r + k_try) % C.n == 0:
            if k is not None:
                raise ValueError("指定的 k 无效(r=0 或 r+k=n)")
            continue
        s = (_modinv(1 + d, C.n) * (k_try - r * d)) % C.n # s=(1+d)^(-1)*(k-r*d) mod n=>k=s+t*d mod n
        if s == 0:
            if k is not None:
                raise ValueError("指定的 k 导致 s=0")
            continue
        return r, s

# 优化二：签名求逆预计算
# SM2 签名公式:  s = ((1+d)^(-1) * (k - r*d)) mod n
# 其中 (1+d)^(-1) mod n 只与私钥 d 有关,与消息/随机数无关。
# 常规实现每次签名都调一次 pow(x, -1, n) 做扩展欧几里得,开销显著;
# 服务端常驻私钥时,把这个逆元预先算好并和 d、ZA 一起缓存,
# 之后每次签名就只剩椭圆曲线点乘 + 两次模乘 + 一次模减,签名吞吐显著提升。

@dataclass(frozen=True)
class SM2SigningKey:
    """提前算好(1+d)^(-1) mod n,下次遇到同一 (私钥, 用户ID)可直接用。"""
    d: int                # 私钥
    pub: Point            # 对应公钥 d*G
    d1_inv: int           # (1 + d)^(-1) mod n
    ZA: bytes             # SM3 预处理值,只依赖 (user_id, pub, 曲线参数)
    user_id: bytes
    curve: SM2Curve

def make_signing_key(d: int, pub: Point | None = None,
                     user_id: bytes = DEFAULT_ID,
                     C: SM2Curve = SM2) -> SM2SigningKey:
    """一次性预计算 (1+d)^(-1) mod n 和 ZA,返回可反复使用的签名句柄。"""
    if not (1 <= d < C.n - 1):
        raise ValueError("私钥 d 必须落在 [1, n-2]")
    if pub is None:
        pub = scalar_mul(d, C.G, C)
    # 基本信赖调用方，对于不合规的情况稍做处理
    if pub is None or not public_key_is_valid(pub, C):
        raise ValueError("公钥不合法或与私钥不匹配")
    if (1 + d) % C.n == 0:
        raise ValueError("(1+d) 恰好为 n 的倍数,该私钥无法用于签名")
    d1_inv = _modinv(1 + d, C.n)
    ZA = compute_ZA(user_id, pub, C)
    return SM2SigningKey(d=d, pub=pub, d1_inv=d1_inv,
                         ZA=ZA, user_id=user_id, curve=C)

def sign_fast(msg: bytes, sk: SM2SigningKey,
              k: int | None = None) -> Tuple[int, int]:
    """使用预计算过的 SM2SigningKey 快速签名,语义等同于 sign()。"""
    C = sk.curve
    e = int.from_bytes(sm3(sk.ZA + msg), "big")
    while True:
        k_try = k if k is not None else (1 + secrets.randbelow(C.n - 1))
        P1 = scalar_mul(k_try, C.G, C)
        if P1 is None:
            if k is not None:
                raise ValueError("指定的 k 生成无穷远点")
            continue
        x1, _ = P1
        r = (e + x1) % C.n
        if r == 0 or (r + k_try) % C.n == 0:
            if k is not None:
                raise ValueError("指定的 k 无效(r=0 或 r+k=n)")
            continue
        # 不再调用 _modinv(1+d, n),直接用预计算的 d1_inv
        s = (sk.d1_inv * (k_try - r * sk.d)) % C.n
        if s == 0:
            if k is not None:
                raise ValueError("指定的 k 导致 s=0")
            continue
        return r, s


def verify(msg: bytes, sig: Tuple[int, int], pub: Point,
           user_id: bytes = DEFAULT_ID, C: SM2Curve = SM2) -> bool:
    # 验签者知道p,a,b,G,n,PA,IDA,M,r,s,并可由此算出t=(r+s)%n,计算P=sG+tQ,若P=P1=kG，则验签成功
    r, s = sig
    if not (1 <= r < C.n and 1 <= s < C.n):
        # 其实r=0,并不会造成什么影响
        return False
    t = (r + s) % C.n# t=(r+s)mod n
    if t == 0:# 实际上，t=0只会导致公钥失效，即验签不依赖公钥，但仍不足以使攻击者伪造签名，因为ZA仍依赖公钥
        return False
    P = point_add(scalar_mul(s, C.G, C), scalar_mul(t, pub, C), C)# P=sG+tQ,Q是公钥=dG
    # 如果签名真实，则有P=(s+t*d)G,由于s+t*d=k,所以P=kG=P1故只需判定P和P1是否为同一点即可，判定其横坐标是否一致
    if P is None:
        return False
    x, _ = P
    # P1横坐标x1有r=(e+x1)%n,所以只需要x有性质r=(e+x)%n即可，计算(e+x)%n=R，那么只需判断R==r?即可
    # 计算e=SM2(ZA||M),ZA=SM2(...)均可由已知数值得到
    ZA = compute_ZA(user_id, pub, C)
    e = int.from_bytes(sm3(ZA + msg), "big")
    R = (e + x) % C.n
    return R == r

# 六、SM2 公钥加密

def _kdf(Z: bytes, klen: int) -> bytes:
    """SM3-based KDF:输出 klen 字节。"""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3(Z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


def encrypt_pke(m: bytes, pub: Point, C: SM2Curve = SM2,
                k: int | None = None) -> bytes:
    """SM2 公钥加密。返回 C1||C3||C2:
        C1 = 04 || x1 || y1   (65 字节, 未压缩点)
        C3 = SM3(x2 || M || y2)  (32 字节)
        C2 = M XOR KDF(x2 || y2, |M|)
    """
    if not public_key_is_valid(pub, C):
        raise ValueError("公钥不合法")
    while True:
        k_try = k if k is not None else (1 + secrets.randbelow(C.n - 1))
        C1 = scalar_mul(k_try, C.G, C)
        S = scalar_mul(k_try, pub, C)
        if S is None:
            if k is not None:
                raise ValueError("指定的 k 得到无穷远点")
            continue
        x2, y2 = S
        t = _kdf(_int_to_bytes(x2, 32) + _int_to_bytes(y2, 32), len(m))
        if all(b == 0 for b in t):
            if k is not None:
                raise ValueError("指定的 k 使 KDF 全 0")
            continue
        C2 = bytes(a ^ b for a, b in zip(m, t))
        C3 = sm3(_int_to_bytes(x2, 32) + m + _int_to_bytes(y2, 32))
        x1, y1 = C1  # type: ignore
        return b"\x04" + _int_to_bytes(x1, 32) + _int_to_bytes(y1, 32) + C3 + C2


def decrypt_pke(ct: bytes, d: int, C: SM2Curve = SM2) -> bytes:
    if len(ct) < 1 + 64 + 32:
        raise ValueError("密文过短")
    if ct[0] != 0x04:
        raise ValueError("仅支持未压缩点格式 (04 前缀)")
    x1 = int.from_bytes(ct[1:33], "big")
    y1 = int.from_bytes(ct[33:65], "big")
    C1 = (x1, y1)
    if not is_on_curve(C1, C):
        raise ValueError("C1 不在曲线上")
    C3 = ct[65:97]
    C2 = ct[97:]
    S = scalar_mul(d, C1, C)
    if S is None:
        raise ValueError("解密失败: d·C1 = O")
    x2, y2 = S
    t = _kdf(_int_to_bytes(x2, 32) + _int_to_bytes(y2, 32), len(C2))
    m = bytes(a ^ b for a, b in zip(C2, t))
    C3_check = sm3(_int_to_bytes(x2, 32) + m + _int_to_bytes(y2, 32))
    if C3_check != C3:
        raise ValueError("完整性校验失败 (C3 不匹配)")
    return m



# 七、自检与演示
SM3_VECTORS = [
    (b"abc",
     bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")),
    (b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
     bytes.fromhex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")),
]


def selftest() -> bool:
    ok = True

    # 1. SM3 官方向量
    for msg, exp in SM3_VECTORS:
        got = sm3(msg)
        good = got == exp
        preview = msg.decode("ascii") if len(msg) <= 8 else msg[:8].decode("ascii") + "..."
        print(f"  [{'PASS' if good else 'FAIL'}] SM3({preview!r:14}) = {got.hex()[:16]}...  "
              f"期望 {exp.hex()[:16]}...")
        ok = ok and good

    # 2. SM2 基点在曲线上、n·G = O
    on = is_on_curve(SM2.G)
    nG = scalar_mul(SM2.n, SM2.G)
    curve_ok = on and (nG is None)
    print(f"  [{'PASS' if curve_ok else 'FAIL'}] SM2 基点在曲线上、n·G = O")
    ok = ok and curve_ok

    # 3. 密钥对合法性
    d, pub = generate_keypair()
    val = public_key_is_valid(pub)
    print(f"  [{'PASS' if val else 'FAIL'}] 新生成公钥通过合法性检查")
    ok = ok and val

    # 4. 签名往返
    msg = "SM2 sign 测试".encode("utf-8")
    sig = sign(msg, d, pub)
    v1 = verify(msg, sig, pub)
    v2 = verify(msg + b"!", sig, pub)
    sign_ok = v1 and (not v2)
    print(f"  [{'PASS' if sign_ok else 'FAIL'}] SM2 签名: 正确={v1}, 篡改={not v2}")
    ok = ok and sign_ok

    # 5. 公钥加密往返
    plain = "SM2 加密 测试 消息".encode("utf-8")
    ct = encrypt_pke(plain, pub)
    back = decrypt_pke(ct, d)
    pke_ok = back == plain
    print(f"  [{'PASS' if pke_ok else 'FAIL'}] SM2-PKE 加解密往返")
    ok = ok and pke_ok

    # 6. 篡改 C3 应导致完整性校验失败
    tampered = bytearray(ct)
    tampered[70] ^= 0xFF
    try:
        decrypt_pke(bytes(tampered), d)
        integ_ok = False
    except ValueError:
        integ_ok = True
    print(f"  [{'PASS' if integ_ok else 'FAIL'}] SM2-PKE 完整性: 篡改 C3 被拒绝")
    ok = ok and integ_ok

    # 7. 优化一: 快速模约减与内建取模等价
    import random as _rnd
    _rnd.seed(0xC0FFEE)
    fast_ok = True
    for _ in range(200):
        v = _rnd.getrandbits(512)      # 覆盖典型的模乘中间值宽度
        if _fast_mod_p(v) != v % SM2.p:
            fast_ok = False
            break
    # 边界值也过一遍
    for v in (0, 1, SM2.p - 1, SM2.p, SM2.p + 1, (1 << 256) - 1, (1 << 512) - 1):
        if _fast_mod_p(v) != v % SM2.p:
            fast_ok = False
            break
    print(f"  [{'PASS' if fast_ok else 'FAIL'}] 快速模约减 _fast_mod_p 与 x % p 等价")
    ok = ok and fast_ok

    # 8. 优化二: sign_fast 与 sign 语义一致且可被 verify 通过
    sk = make_signing_key(d, pub)
    k_fixed = 1 + secrets.randbelow(SM2.n - 1)
    r1, s1 = sign(msg, d, pub, k=k_fixed)
    r2, s2 = sign_fast(msg, sk, k=k_fixed)
    same = (r1, s1) == (r2, s2)
    v_fast = verify(msg, (r2, s2), pub)
    print(f"  [{'PASS' if (same and v_fast) else 'FAIL'}] sign_fast 与 sign 结果一致且可验签")
    ok = ok and same and v_fast

    # 9. 优化二: 简单基准,展示预计算带来的加速比
    import time as _t
    N = 30
    t0 = _t.perf_counter()
    for _ in range(N):
        sign(msg, d, pub)
    t_slow = _t.perf_counter() - t0
    t0 = _t.perf_counter()
    for _ in range(N):
        sign_fast(msg, sk)
    t_fast = _t.perf_counter() - t0
    speedup = t_slow / t_fast if t_fast > 0 else float("inf")
    print(f"  [INFO] 签名基准 N={N}: sign={t_slow*1000:.1f}ms  "
          f"sign_fast={t_fast*1000:.1f}ms  加速 x{speedup:.2f}")

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


def demo() -> None:
    print("SM2 国密 完整演示")
    print("1) 生成密钥对")
    d, pub = generate_keypair()
    print(f"d (私) = {hex(d)[:34]}...")
    print(f"Q.x    = {hex(pub[0])[:34]}...")  # type: ignore
    print(f"Q.y    = {hex(pub[1])[:34]}...")  # type: ignore
    print(f"合法性 = {public_key_is_valid(pub)}")

    print()
    print("2) ZA 预处理 (创新点: 把用户身份注入签名)")
    ZA = compute_ZA(DEFAULT_ID, pub)
    print(f"用户 ID  : {DEFAULT_ID.decode()}")
    print(f"ZA (SM3): {ZA.hex()}")

    print()
    print("3) SM2 数字签名")
    msg = "hello SM2 数字签名 2026".encode("utf-8")
    sig = sign(msg, d, pub)
    print(f"消息 : {msg.decode('utf-8')}")
    print(f"(r, s) = ({hex(sig[0])[:20]}..., {hex(sig[1])[:20]}...)")
    print(f"验证 : {verify(msg, sig, pub)}")
    print(f"篡改 : {verify(msg + b'?', sig, pub)}(应为 False)")

    print()
    print("4) SM2 公钥加密 (C1||C3||C2)")
    plain = "SM2-PKE 演示 明文 message".encode("utf-8")
    ct = encrypt_pke(plain, pub)
    back = decrypt_pke(ct, d)
    print(f"明文  : {plain.decode('utf-8')}")
    print(f"密文  : 04 || x1(32) || y1(32) || C3(32) || C2({len(plain)})")
    print(f"      hex[:64] = {ct.hex()[:64]}...")
    print(f"解密  : {back.decode('utf-8')}")


def main() -> int:
    ap = argparse.ArgumentParser(description="SM3 + SM2-DSA + SM2-PKE")
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
