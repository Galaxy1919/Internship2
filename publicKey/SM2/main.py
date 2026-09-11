#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 国密椭圆曲线密码从零实现
==============================

原理
----
SM2 是中国国家密码管理局发布的椭圆曲线公钥密码算法(GM/T 0003-2012),
使用固定的 256-bit 素数域曲线,提供三个组件:

  1) 密钥交换协议(SM2-KE)  -- 本文件未实现,课堂暂略
  2) 数字签名算法 (SM2-DSA) -- 本文件重点实现
  3) 公钥加密算法 (SM2-PKE) -- 本文件重点实现

曲线方程和 ECC 一样是短 Weierstrass 形式:
    y^2 = x^3 + a·x + b  (mod p)
但参数是国家标准指定的固定值(见 GM/T 0003.5),与 secp256k1 / P-256
都不同。基点 G 的阶 n 为大素数。

SM2 与国际主流(ECDSA、ECIES)的关键区别:
  - 摘要函数用 SM3(而非 SHA-256)
  - 签名时把用户标识 ID 与公钥一起并入 ZA 预处理值,再和消息一起哈希,
    起到"绑定身份"的作用,防跨用户重放
  - 加密算法(SM2-PKE)基于 KDF 派生密钥再异或,同时附加 C3 = SM3(x2||M||y2)
    做完整性校验,输出布局为 C1 || C3 || C2(GM/T 0003.4-2012)

创新点
------
1. **从零实现 SM3**:课堂常见做法是调用 gmssl 等外部库,本文件手写 SM3,
   直接对齐 GM/T 0004-2012 的官方测试向量 "abc" 与 512-bit 长消息。
2. **教学化的 ZA 预处理**:显式打印 ZA 的组成部分,让学生看到 SM2 如何
   把"用户身份"注入签名。
3. **合法性检查**:仿照 ECC 教学模块,给出公钥四项校验(在曲线上、非
   无穷远、坐标在 [0, p)、n·PubKey = O),防小子群/无效曲线攻击。

注意
----
本实现只做 SM2 的数学核心,未做 ASN.1/DER 编码,也没有实现密钥交换。
仅用于课程演示,请勿在生产场景使用。

运行方式
--------
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

# ---------------------------------------------------------------------------
# 一、SM3 摘要函数(手写实现,对齐 GM/T 0004-2012)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 二、SM2 曲线参数(GM/T 0003.5-2012 推荐参数)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 三、椭圆曲线群运算(与 publicKey/ECC 模块保持一致的教学接口)
# ---------------------------------------------------------------------------

def _modinv(x: int, p: int) -> int:# 模逆运算
    return pow(x, -1, p)


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


# ---------------------------------------------------------------------------
# 四、密钥对与 ZA 预处理
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 五、SM2 数字签名
# ---------------------------------------------------------------------------

DEFAULT_ID = b"1234567812345678"  # GM/T 0003.5 默认标识


def sign(msg: bytes, d: int, pub: Point, user_id: bytes = DEFAULT_ID,
         C: SM2Curve = SM2, k: int | None = None) -> Tuple[int, int]:
    """SM2 签名 (r, s)。k 可选,便于向量对齐/攻击演示。"""
    ZA = compute_ZA(user_id, pub, C)
    e = int.from_bytes(sm3(ZA + msg), "big") # e=SM3(ZA||M)
    while True:
        k_try = k if k is not None else (1 + secrets.randbelow(C.n - 1))# 随机选取k
        P1 = scalar_mul(k_try, C.G, C)# P1=kG
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
        s = (_modinv(1 + d, C.n) * (k_try - r * d)) % C.n
        if s == 0:
            if k is not None:
                raise ValueError("指定的 k 导致 s=0")
            continue
        return r, s


def verify(msg: bytes, sig: Tuple[int, int], pub: Point,
           user_id: bytes = DEFAULT_ID, C: SM2Curve = SM2) -> bool:
    r, s = sig
    if not (1 <= r < C.n and 1 <= s < C.n):
        return False
    ZA = compute_ZA(user_id, pub, C)
    e = int.from_bytes(sm3(ZA + msg), "big")
    t = (r + s) % C.n
    if t == 0:
        return False
    P = point_add(scalar_mul(s, C.G, C), scalar_mul(t, pub, C), C)# P=sG+tQ,Q是公钥
    if P is None:
        return False
    x1, _ = P
    R = (e + x1) % C.n
    return R == r


# ---------------------------------------------------------------------------
# 六、SM2 公钥加密(GM/T 0003.4-2012, C1 || C3 || C2 输出)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 七、自检与演示
# ---------------------------------------------------------------------------

# GM/T 0004-2012 官方 SM3 测试向量
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

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


def demo() -> None:
    print("=" * 60)
    print("SM2 国密 完整演示")
    print("=" * 60)

    print("1) 生成密钥对")
    d, pub = generate_keypair()
    print(f"   d (私) = {hex(d)[:34]}...")
    print(f"   Q.x    = {hex(pub[0])[:34]}...")  # type: ignore
    print(f"   Q.y    = {hex(pub[1])[:34]}...")  # type: ignore
    print(f"   合法性 = {public_key_is_valid(pub)}")

    print()
    print("2) ZA 预处理 (创新点: 把用户身份注入签名)")
    ZA = compute_ZA(DEFAULT_ID, pub)
    print(f"   用户 ID  : {DEFAULT_ID.decode()}")
    print(f"   ZA (SM3): {ZA.hex()}")

    print()
    print("3) SM2 数字签名")
    msg = "hello SM2 数字签名 2026".encode("utf-8")
    sig = sign(msg, d, pub)
    print(f"   消息 : {msg.decode('utf-8')}")
    print(f"   (r, s) = ({hex(sig[0])[:20]}..., {hex(sig[1])[:20]}...)")
    print(f"   验证 : {verify(msg, sig, pub)}")
    print(f"   篡改 : {verify(msg + b'?', sig, pub)}(应为 False)")

    print()
    print("4) SM2 公钥加密 (C1||C3||C2)")
    plain = "SM2-PKE 演示 明文 message".encode("utf-8")
    ct = encrypt_pke(plain, pub)
    back = decrypt_pke(ct, d)
    print(f"   明文  : {plain.decode('utf-8')}")
    print(f"   密文  : 04 || x1(32) || y1(32) || C3(32) || C2({len(plain)})")
    print(f"         hex[:64] = {ct.hex()[:64]}...")
    print(f"   解密  : {back.decode('utf-8')}")


def main() -> int:
    ap = argparse.ArgumentParser(description="SM2 国密从零实现 (SM3 + SM2-DSA + SM2-PKE)")
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
