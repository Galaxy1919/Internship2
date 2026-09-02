#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECC(椭圆曲线密码学)教学实现
===============================

原理
----
在质数域 Fp 上,选取一条方程为

    y^2 ≡ x^3 + a·x + b   (mod p)

的椭圆曲线,取一个基点 G,并要求 G 的阶为大素数 n。
曲线上"点集 + 无穷远点 O"在特定加法规则下构成阿贝尔群:

1. 单位元:无穷远点 O(用 None 表示)
2. 逆元:  -P = (x, -y mod p)
3. 加法:  P + Q,分三种情形
     (a) P = O 或 Q = O                   -> 直接返回另一个
     (b) P + (-P) = O
     (c) P ≠ Q 时     λ = (yQ - yP) / (xQ - xP)
         P = Q 时(倍点)  λ = (3·xP² + a) / (2·yP)
         x_R = λ² - xP - xQ
         y_R = λ·(xP - x_R) - yP
   除法在有限域里是"乘以逆元",用扩展欧几里得或 pow(x, -1, p)。

4. 标量乘 k·P:用"平方-乘"的加法版本(double-and-add),即遍历 k 的
   二进制,每一位都先"倍点"一次,遇到 1 就"加基点"一次。
   复杂度 O(log k) 次点运算。

ECC 的安全性依赖 ECDLP(椭圆曲线离散对数问题):已知 P、Q,求 k 使
Q = k·P 极其困难。相同安全等级下,ECC 的密钥比 RSA/DH 短得多
(例如 256-bit ECC ≈ 3072-bit RSA)。

------------------------------------------------------------------
本模块包含
    1) 有限域上的椭圆曲线抽象 `Curve` 和点运算原语
    2) 一条教学小曲线 y^2 = x^3 + 2x + 2 (mod 17),阶 n = 19
       -- 用来在课堂上手算验证
    3) secp256k1 完整参数,用于真实规模的 ECDH 密钥交换
    4) ECDH:Alice/Bob 各生成密钥对,交换公钥,双方独立算出同一个共享点
    5) 创新点 1:**可审计的 double-and-add 轨迹**
       每一步都记录"这轮是倍点还是加基点、中间点是什么",输出到日志,
       让学生直接看到标量乘法内部
    6) 创新点 2:**公钥合法性检查**(小子群/无效曲线攻击的入门演示)
       - 检查公钥是否在曲线上
       - 检查公钥不是无穷远点
       - 检查 n·PubKey == O (基点子群成员测试)
    7) 自检:secp256k1 已知向量 (G·1 = G, G·n = O, G·2 已知)
"""
from __future__ import annotations

import argparse
import secrets
import sys
from dataclasses import dataclass
from typing import Optional, Tuple, List


# 用 (x, y) 表示有限点,用 None 表示无穷远点 O
Point = Optional[Tuple[int, int]]


# ---------------------------------------------------------------------------
# 曲线参数
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Curve:
    """短 Weierstrass 形式椭圆曲线 y^2 = x^3 + a·x + b (mod p)。"""
    name: str
    p: int          # 有限域特征(大质数)
    a: int
    b: int
    Gx: int
    Gy: int
    n: int          # 基点 G 的阶(大质数)

    @property
    def G(self) -> Point:
        return (self.Gx, self.Gy)


# 教学小曲线:y^2 = x^3 + 2x + 2 (mod 17),基点 G = (5, 1),阶 n = 19
# 参数很小,便于手算验证每一步是否正确
TOY = Curve(
    name="toy-p17",
    p=17, a=2, b=2,
    Gx=5, Gy=1,
    n=19,
)

# secp256k1(比特币同款曲线):y^2 = x^3 + 7 (mod p)
SECP256K1 = Curve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


# ---------------------------------------------------------------------------
# 有限域运算(只用一个:模逆)
# ---------------------------------------------------------------------------

def modinv(x: int, p: int) -> int:
    """有限域 Fp 里的乘法逆:x·y ≡ 1 (mod p)。

    Python 3.8+ 的 pow 支持负指数,等价于扩展欧几里得,
    这里包一层是为了在 x % p == 0 时抛出更友好的错误。
    """
    if x % p == 0:
        raise ZeroDivisionError("0 在有限域里没有乘法逆元")
    return pow(x, -1, p)


# ---------------------------------------------------------------------------
# 椭圆曲线群运算
# ---------------------------------------------------------------------------

def is_on_curve(P: Point, C: Curve) -> bool:
    """判断点 P 是否落在曲线 C 上。无穷远点 O 视为在。"""
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + C.a * x + C.b)) % C.p == 0


def point_neg(P: Point, C: Curve) -> Point:
    if P is None:
        return None
    x, y = P
    return (x, (-y) % C.p)


def point_add(P: Point, Q: Point, C: Curve) -> Point:
    """计算 P + Q,严格覆盖所有边界情形。"""
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # 情形 (b):P = -Q,和为无穷远
    if x1 == x2 and (y1 + y2) % C.p == 0:
        return None

    if P == Q:
        # 倍点:λ = (3·x1² + a) / (2·y1)
        lam = (3 * x1 * x1 + C.a) * modinv(2 * y1, C.p) % C.p
    else:
        # 一般加法:λ = (y2 - y1) / (x2 - x1)
        lam = (y2 - y1) * modinv(x2 - x1, C.p) % C.p

    x3 = (lam * lam - x1 - x2) % C.p
    y3 = (lam * (x1 - x3) - y1) % C.p
    return (x3, y3)


def scalar_mul(k: int, P: Point, C: Curve,
               trace: Optional[List[Tuple[str, int, Point]]] = None) -> Point:
    """标量乘 k·P,基于 double-and-add。

    若传入 trace 列表,则每一步"倍点/加"操作会被记录下来,方便课堂演示。
    对负数 k 转换成 |k|·(-P)。
    """
    if k == 0 or P is None:
        return None
    if k < 0:
        return scalar_mul(-k, point_neg(P, C), C, trace)

    result: Point = None       # 累加器初始为 O
    addend: Point = P          # 当前"底"

    bit_index = 0
    while k > 0:
        if k & 1:
            result = point_add(result, addend, C)
            if trace is not None:
                trace.append(("add", bit_index, result))
        addend = point_add(addend, addend, C)         # 倍点
        if trace is not None and (k >> 1) > 0:
            trace.append(("double", bit_index, addend))
        k >>= 1
        bit_index += 1
    return result


# ---------------------------------------------------------------------------
# 密钥对与 ECDH
# ---------------------------------------------------------------------------

def generate_keypair(C: Curve, rng=None) -> Tuple[int, Point]:
    """在 [1, n-1] 上随机取私钥 d,返回 (d, d·G)。"""
    if rng is None:
        d = 1 + secrets.randbelow(C.n - 1)
    else:
        d = rng()
    return d, scalar_mul(d, C.G, C)


def public_key_is_valid(pub: Point, C: Curve) -> bool:
    """公钥合法性检查:非无穷远、落在曲线上、位于阶为 n 的子群。"""
    if pub is None:
        return False
    x, y = pub
    if not (0 <= x < C.p and 0 <= y < C.p):
        return False
    if not is_on_curve(pub, C):
        return False
    # 子群成员测试:n·PubKey 必须回到无穷远
    return scalar_mul(C.n, pub, C) is None


def ecdh(my_priv: int, peer_pub: Point, C: Curve) -> Point:
    """计算共享点 S = my_priv · peer_pub。

    双方独立计算出的 S 相同:
        Alice: dA · (dB·G) = dA·dB·G
        Bob:   dB · (dA·G) = dA·dB·G
    真实协议里,应把 S 的 x 坐标喂给 KDF 派生对称密钥。
    """
    if not public_key_is_valid(peer_pub, C):
        raise ValueError("对端公钥不合法(曲线外、无穷远或不在正确子群)")
    return scalar_mul(my_priv, peer_pub, C)


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

# secp256k1 的 2G 是公开已知向量(常见于比特币教材)
SECP256K1_2G_X = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
SECP256K1_2G_Y = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A


def selftest() -> bool:
    """把关键性质挨个跑一遍。"""
    ok = True

    # 1. 教学小曲线:基点在曲线上
    on = is_on_curve(TOY.G, TOY)
    print(f"  [{'PASS' if on else 'FAIL'}] toy 基点 G=(5,1) 在曲线 y^2=x^3+2x+2 mod 17 上")
    ok = ok and on

    # 2. 教学小曲线:2G 手算值 (6, 3)
    two_g = scalar_mul(2, TOY.G, TOY)
    two_g_ok = two_g == (6, 3)
    print(f"  [{'PASS' if two_g_ok else 'FAIL'}] toy 曲线 2G = {two_g},期望 (6, 3)")
    ok = ok and two_g_ok

    # 3. 教学小曲线:n·G = O
    nG = scalar_mul(TOY.n, TOY.G, TOY)
    nG_ok = nG is None
    print(f"  [{'PASS' if nG_ok else 'FAIL'}] toy 曲线 19·G = {nG},期望 O(None)")
    ok = ok and nG_ok

    # 4. secp256k1:G·1 = G
    g1 = scalar_mul(1, SECP256K1.G, SECP256K1)
    g1_ok = g1 == SECP256K1.G
    print(f"  [{'PASS' if g1_ok else 'FAIL'}] secp256k1 1·G == G")
    ok = ok and g1_ok

    # 5. secp256k1:2G 与已知向量对齐
    g2 = scalar_mul(2, SECP256K1.G, SECP256K1)
    g2_ok = g2 == (SECP256K1_2G_X, SECP256K1_2G_Y)
    print(f"  [{'PASS' if g2_ok else 'FAIL'}] secp256k1 2·G 与公开向量一致")
    ok = ok and g2_ok

    # 6. secp256k1:n·G = O
    ng = scalar_mul(SECP256K1.n, SECP256K1.G, SECP256K1)
    ng_ok = ng is None
    print(f"  [{'PASS' if ng_ok else 'FAIL'}] secp256k1 n·G == O")
    ok = ok and ng_ok

    # 7. ECDH 一致性
    dA, QA = generate_keypair(SECP256K1)
    dB, QB = generate_keypair(SECP256K1)
    SA = ecdh(dA, QB, SECP256K1)
    SB = ecdh(dB, QA, SECP256K1)
    dh_ok = SA == SB and SA is not None
    print(f"  [{'PASS' if dh_ok else 'FAIL'}] ECDH 双方共享点一致 (secp256k1)")
    ok = ok and dh_ok

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


# ---------------------------------------------------------------------------
# 演示
# ---------------------------------------------------------------------------

def demo_toy_trace() -> None:
    """在教学小曲线上打印 7·G 的完整 double-and-add 轨迹。"""
    print("=" * 60)
    print("创新点 1:可审计的 double-and-add 轨迹(toy 曲线,k = 7)")
    print("=" * 60)
    trace: List[Tuple[str, int, Point]] = []
    R = scalar_mul(7, TOY.G, TOY, trace=trace)
    for op, bit, pt in trace:
        print(f"  bit={bit}  {op:6s}  -> {pt}")
    print(f"  最终 7·G = {R}")


def demo_ecdh() -> None:
    """在 secp256k1 上做一次 ECDH,展示合法性检查。"""
    print("=" * 60)
    print("secp256k1 ECDH 密钥交换")
    print("=" * 60)
    dA, QA = generate_keypair(SECP256K1)
    dB, QB = generate_keypair(SECP256K1)
    print(f"Alice 私钥 dA = {hex(dA)}")
    print(f"Alice 公钥 QA.x = {hex(QA[0])}")
    print(f"Bob   私钥 dB = {hex(dB)}")
    print(f"Bob   公钥 QB.x = {hex(QB[0])}")

    # 创新点 2:公钥合法性检查
    print()
    print("创新点 2:公钥合法性检查")
    print(f"  Alice 公钥合法? {public_key_is_valid(QA, SECP256K1)}")
    print(f"  Bob   公钥合法? {public_key_is_valid(QB, SECP256K1)}")
    # 反例:曲线外的点
    fake = (QA[0], (QA[1] + 1) % SECP256K1.p)
    print(f"  篡改一位 y 得到的伪公钥合法? {public_key_is_valid(fake, SECP256K1)}(应为 False)")

    SA = ecdh(dA, QB, SECP256K1)
    SB = ecdh(dB, QA, SECP256K1)
    print()
    print(f"Alice 侧共享点.x = {hex(SA[0])}")
    print(f"Bob   侧共享点.x = {hex(SB[0])}")
    print("共享一致:", "PASS" if SA == SB else "FAIL")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="ECC 教学实现:toy 曲线 + secp256k1 ECDH")
    parser.add_argument("--selftest", action="store_true", help="运行自检向量")
    parser.add_argument("--toy", action="store_true", help="教学小曲线 + 可审计轨迹")
    parser.add_argument("--ecdh", action="store_true", help="secp256k1 上做一次 ECDH")
    args = parser.parse_args()

    if not (args.selftest or args.toy or args.ecdh):
        # 默认:全部跑一遍
        selftest()
        print()
        demo_toy_trace()
        print()
        demo_ecdh()
        return 0

    if args.selftest and not selftest():
        return 1
    if args.toy:
        print()
        demo_toy_trace()
    if args.ecdh:
        print()
        demo_ecdh()
    return 0


if __name__ == "__main__":
    sys.exit(main())
