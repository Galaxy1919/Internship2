#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多表替代密码（Polyalphabetic Substitution）
============================================

原理
----
单表替代整篇密文只换同一张表，因此同频字母仍然同形，易被频率分析攻破。
多表替代用 *多张* 替换表轮流加密：第 i 个明文字母用第 (i mod 密钥长) 张表，
同一个明文字母在不同位置会被加密成不同密文字母，从而打散频率特征。

本模块实现任务书列出的全部三种多表替代密码（用同一张 Vigenère 方阵）：

1. Vigenere（维吉尼亚）—— 密钥周期重复
       keystream[i] = key[i mod len(key)]
2. Autokey plaintext（自动密钥-明文）—— 密钥后接 *明文*
       keystream = key + plaintext
3. Autokey ciphertext（自动密钥-密文）—— 密钥后接 *密文*
       keystream = key + ciphertext

    明文:  ATTACKATDAWN
    Vigenere(密钥 LEMON):   LXFOPVEFRNHR
    Autokey-明文(QUEENLY):  QNXEPVYTWTWP
    Autokey-密文(密钥 KEX): （见 selftest）

创新点：附带“密钥周期”与“列重合指数”对照实验
----------------------------------------------
Vigenere 的密钥周期重复是致命弱点：用 Friedman 检验（列重合指数，即按周期
把密文切成若干列，再算每列 IC 的平均值）能定位出真实周期——真实周期那一切
的列 IC 接近自然语言（≈0.0667），错误周期接近随机（≈0.0385）。而 Autokey 两
种变体密钥不周期重复，故不存在这样的峰值。本模块提供 coincidence_index()
与 column_ic()，可对三种密文定量对比，供实验报告引用。全部仅用标准库实现。

运行方式
--------
    python main.py                          # 交互模式
    python main.py -m encrypt -k LEMON -t ATTACKATDAWN   # 命令行加密
    python main.py -m decrypt -k LEMON -t LXFOPVEFRNHR   # 命令行解密
    python main.py --variant autokey-plaintext ...
    python main.py --selftest               # 已知向量自检 + IC 对比
"""

import argparse
import sys
from pathlib import Path

# 三种变体标识
VIGENERE = "vigenere"
AUTOKEY_PLAINTEXT = "autokey-plaintext"
AUTOKEY_CIPHERTEXT = "autokey-ciphertext"
VARIANTS = (VIGENERE, AUTOKEY_PLAINTEXT, AUTOKEY_CIPHERTEXT)


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def letters_only(text: str) -> str:
    """保留 A-Z 字母并转大写，丢弃空格、标点、数字等其它字符。"""
    return "".join(ch for ch in text.upper() if ch.isalpha())


def _shift(c: str, k: str, decrypt: bool = False) -> str:
    """对单个字母做一次 Caesar 移位：加密加、解密减，模 26。"""
    sign = -1 if decrypt else 1
    return chr((ord(c) - ord("A") + sign * (ord(k) - ord("A"))) % 26 + ord("A"))


def _build_keystream(plain_or_cipher: str, key: str, variant: str) -> str:
    """按变体构造与消息等长的密钥流。"""
    if variant == VIGENERE:
        n = len(plain_or_cipher)
        return (key * (n // len(key) + 1))[:n]
    if variant == AUTOKEY_PLAINTEXT:
        # 密钥流 = 密钥词 + 明文本身（只取到消息长度为止）
        return (key + plain_or_cipher)[:len(plain_or_cipher)]
    if variant == AUTOKEY_CIPHERTEXT:
        # 密钥流 = 密钥词 + 已生成的密文；这里由调用方传入密文作为尾部来源
        return (key + plain_or_cipher)[:len(plain_or_cipher)]
    raise ValueError(f"未知变体: {variant}")


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def vigenere_encrypt(plain: str, key: str) -> str:
    """Vigenere 加密：密钥周期重复。"""
    plain = letters_only(plain)
    key = letters_only(key)
    if not key:
        raise ValueError("密钥不能为空")
    return "".join(_shift(p, k) for p, k in zip(plain, _build_keystream(plain, key, VIGENERE)))


def vigenere_decrypt(cipher: str, key: str) -> str:
    """Vigenere 解密。"""
    cipher = letters_only(cipher)
    key = letters_only(key)
    if not key:
        raise ValueError("密钥不能为空")
    return "".join(_shift(c, k, decrypt=True) for c, k in zip(cipher, _build_keystream(cipher, key, VIGENERE)))


def autokey_plaintext_encrypt(plain: str, key: str) -> str:
    """Autokey-明文 加密：keystream = 密钥 + 明文。"""
    plain = letters_only(plain)
    key = letters_only(key)
    if not key:
        raise ValueError("密钥不能为空")
    ks = _build_keystream(plain, key, AUTOKEY_PLAINTEXT)
    return "".join(_shift(p, k) for p, k in zip(plain, ks))


def autokey_plaintext_decrypt(cipher: str, key: str) -> str:
    """Autokey-明文 解密：先恢复密钥词前缀，随后逐位用已解出的明文续密钥。"""
    cipher = letters_only(cipher)
    key = letters_only(key)
    if not key:
        raise ValueError("密钥不能为空")
    out = []
    for i, c in enumerate(cipher):
        k = key[i] if i < len(key) else out[i - len(key)]
        out.append(_shift(c, k, decrypt=True))
    return "".join(out)


def autokey_ciphertext_encrypt(plain: str, key: str) -> str:
    """Autokey-密文 加密：keystream = 密钥 + 已生成密文。"""
    plain = letters_only(plain)
    key = letters_only(key)
    if not key:
        raise ValueError("密钥不能为空")
    out = []
    for i, p in enumerate(plain):
        k = key[i] if i < len(key) else out[i - len(key)]
        out.append(_shift(p, k))
    return "".join(out)


def autokey_ciphertext_decrypt(cipher: str, key: str) -> str:
    """Autokey-密文 解密：密钥尾部直接取自已收到的密文。"""
    cipher = letters_only(cipher)
    key = letters_only(key)
    if not key:
        raise ValueError("密钥不能为空")
    out = []
    for i, c in enumerate(cipher):
        k = key[i] if i < len(key) else cipher[i - len(key)]
        out.append(_shift(c, k, decrypt=True))
    return "".join(out)


def encrypt(plain: str, key: str, variant: str = VIGENERE) -> str:
    """统一加密入口，按 variant 分派。"""
    if variant == VIGENERE:
        return vigenere_encrypt(plain, key)
    if variant == AUTOKEY_PLAINTEXT:
        return autokey_plaintext_encrypt(plain, key)
    if variant == AUTOKEY_CIPHERTEXT:
        return autokey_ciphertext_encrypt(plain, key)
    raise ValueError(f"未知变体: {variant}")


def decrypt(cipher: str, key: str, variant: str = VIGENERE) -> str:
    """统一解密入口，按 variant 分派。"""
    if variant == VIGENERE:
        return vigenere_decrypt(cipher, key)
    if variant == AUTOKEY_PLAINTEXT:
        return autokey_plaintext_decrypt(cipher, key)
    if variant == AUTOKEY_CIPHERTEXT:
        return autokey_ciphertext_decrypt(cipher, key)
    raise ValueError(f"未知变体: {variant}")


# ---------------------------------------------------------------------------
# 创新点：可审计轨迹 + 重合指数对比
# ---------------------------------------------------------------------------

def trace(plain: str, key: str, variant: str = VIGENERE) -> dict:
    """返回逐位对齐表（明文/密钥流/密文），便于写入报告并逐步验算。"""
    plain = letters_only(plain)
    key = letters_only(key)
    if variant == VIGENERE:
        ks = _build_keystream(plain, key, VIGENERE)
    elif variant == AUTOKEY_PLAINTEXT:
        ks = (key + plain)[:len(plain)]
    elif variant == AUTOKEY_CIPHERTEXT:
        cipher = autokey_ciphertext_encrypt(plain, key)
        ks = (key + cipher)[:len(plain)]
    else:
        raise ValueError(f"未知变体: {variant}")
    cipher = "".join(_shift(p, k) for p, k in zip(plain, ks))
    return {"plain": plain, "keystream": ks, "cipher": cipher}


def coincidence_index(text: str) -> float:
    """重合指数 IC = Σ n_i(n_i-1) / (N(N-1))，N 为字母总数。

    英文自然语言 IC≈0.0667，完全随机 IC≈0.0385。
    """
    text = letters_only(text)
    n = len(text)
    if n < 2:
        return 0.0
    freq = [text.count(ch) for ch in set(text)]
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def column_ic(text: str, period: int) -> float:
    """按给定周期把密文切成 period 列，返回各列 IC 的平均值（Friedman 检验）。

    若 period 恰为真实密钥长度，每列都是一次独立的 Caesar 移位，保留自然语言
    的字母分布，平均 IC 会明显高于其它周期——这就是定位 Vigenere 密钥长度的
    经典方法。Autokey 变体密钥不周期，故任何 period 都测不出明显峰值。
    """
    text = letters_only(text)
    if period <= 0:
        raise ValueError("周期必须为正数")
    cols = [text[i::period] for i in range(period)]
    cols = [c for c in cols if len(c) >= 2]     # 太短的列不参与统计
    if not cols:
        return 0.0
    return sum(coincidence_index(c) for c in cols) / len(cols)


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

def selftest() -> bool:
    ok = True

    def check(tag, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {tag}: {got}   期望 {want}")

    print("已知向量:")
    # 1. Vigenere：密钥 LEMON，明文 ATTACKATDAWN（Wikipedia 经典例）
    check("Vigenere  LEMON/ATTACKATDAWN",
          vigenere_encrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")
    check("Vigenere  解密回环",
          vigenere_decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN")

    # 2. Autokey-明文：密钥 QUEENLY，明文 attackatdawn（Wikipedia 经典例）
    check("AutokeyP  QUEENLY/ATTACKATDAWN",
          autokey_plaintext_encrypt("ATTACKATDAWN", "QUEENLY"), "QNXEPVYTWTWP")
    check("AutokeyP  解密回环",
          autokey_plaintext_decrypt("QNXEPVYTWTWP", "QUEENLY"), "ATTACKATDAWN")

    # 3. Autokey-密文：手算向量 密钥 KEY，明文 ATTACK -> KXRKZB
    check("AutokeyC  KEY/ATTACK",
          autokey_ciphertext_encrypt("ATTACK", "KEY"), "KXRKZB")
    check("AutokeyC  解密回环",
          autokey_ciphertext_decrypt("KXRKZB", "KEY"), "ATTACK")

    # 4. 三种变体统一入口往返一致
    print("往返一致性:")
    for variant in VARIANTS:
        for p, k in [("Meet me at midnight", "SECRET"),
                     ("The quick brown fox", "LEMON"),
                     ("Information security", "CRYPT")]:
            c = encrypt(p, k, variant)
            back = decrypt(c, k, variant)
            norm = letters_only(p)
            good = back == norm
            ok = ok and good
            print(f"  [{'PASS' if good else 'FAIL'}] {variant:20s} {k:6s} "
                  f"{norm:22s} -> {c}  还原={back}")

    print("列重合指数对照（创新点）:")
    # 用一段足够长的自然语言文本，比较“真实周期(5)”与“错误周期(4/6)”的列 IC。
    long_plain = letters_only(
        "it was the best of times it was the worst of times "
        "it was the age of wisdom it was the age of foolishness " * 3)
    vc = encrypt(long_plain, "LEMON", VIGENERE)
    print(f"  Vigenere 密文 列IC 周期4={column_ic(vc, 4):.4f}  "
          f"周期5={column_ic(vc, 5):.4f}  周期6={column_ic(vc, 6):.4f}   ← 周期5 出现峰值")
    ap = encrypt(long_plain, "LEMON", AUTOKEY_PLAINTEXT)
    ac = encrypt(long_plain, "LEMON", AUTOKEY_CIPHERTEXT)
    print(f"  Autokey-明文  列IC 周期4={column_ic(ap, 4):.4f}  "
          f"周期5={column_ic(ap, 5):.4f}  周期6={column_ic(ap, 6):.4f}")
    print(f"  Autokey-密文  列IC 周期4={column_ic(ac, 4):.4f}  "
          f"周期5={column_ic(ac, 5):.4f}  周期6={column_ic(ac, 6):.4f}")
    print("  （Autokey 两种变体无周期峰值，故 Friedman 检验失效）")

    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive() -> None:
    print("=" * 50)
    print("多表替代密码（Vigenere / Autokey）")
    print("=" * 50)
    key = input("输入密钥词: ").strip() or "LEMON"
    plain = input("输入明文: ").strip() or "ATTACKATDAWN"
    for variant in VARIANTS:
        info = trace(plain, key, variant)
        print("-" * 50)
        print(f"变体      : {variant}")
        print(f"明文      : {info['plain']}")
        print(f"密钥流    : {info['keystream']}")
        print(f"密文      : {info['cipher']}")
        print(f"解密还原  : {decrypt(info['cipher'], key, variant)}")
        print(f"重合指数  : {coincidence_index(info['cipher']):.4f}")


def main() -> int:
    parser = argparse.ArgumentParser(description="多表替代密码（Vigenere / Autokey）")
    parser.add_argument("-k", "--key", required=False, help="密钥词")
    parser.add_argument("-t", "--text", help="要处理的文本（明文或密文）")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt"],
                        default="encrypt", help="加密还是解密（默认 encrypt）")
    parser.add_argument("--variant", choices=VARIANTS, default=VIGENERE,
                        help="多表替代变体（默认 vigenere）")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.selftest:
        return 0 if selftest() else 1

    if args.key is not None and args.text is not None:
        try:
            result = (encrypt if args.mode == "encrypt" else decrypt)(
                args.text, args.key, args.variant)
        except ValueError as exc:
            print(f"错误: {exc}", file=sys.stderr)
            return 1
        print(f"变体      : {args.variant}")
        print(f"密钥词    : {args.key}")
        print(f"模式      : {args.mode}")
        print(f"输入      : {letters_only(args.text)}")
        print(f"输出      : {result}")
        return 0

    interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
