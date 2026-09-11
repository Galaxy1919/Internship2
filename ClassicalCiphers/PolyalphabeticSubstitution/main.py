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
VARIANTS = (VIGENERE, AUTOKEY_PLAINTEXT, AUTOKEY_CIPHERTEXT)  # 三种变体清单


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def letters_only(text: str) -> str:
    """保留 A-Z 字母并转大写，丢弃空格、标点、数字等其它字符。"""
    return "".join(ch for ch in text.upper() if ch.isalpha())  # 转大写 + 只留字母


def _shift(c: str, k: str, decrypt: bool = False) -> str:
    """对单个字母做一次 Caesar 移位：加密加、解密减，模 26。"""
    sign = -1 if decrypt else 1                       # 解密取负(减),加密取正(加)
    # ord(c)-ord('A') 把字母映射到 0..25,再加 sign*密钥位移,模 26 后加回 'A' 还原字母
    return chr((ord(c) - ord("A") + sign * (ord(k) - ord("A"))) % 26 + ord("A"))


def _build_keystream(plain_or_cipher: str, key: str, variant: str) -> str:
    """按变体构造与消息等长的密钥流。"""
    if variant == VIGENERE:
        # Vigenere:密钥循环重复。把 key 拉长到至少 n 位,再截前 n 位
        n = len(plain_or_cipher)
        return (key * (n // len(key) + 1))[:n]
    if variant == AUTOKEY_PLAINTEXT:
        # 密钥流 = 密钥词 + 明文本身（只取到消息长度为止）
        return (key + plain_or_cipher)[:len(plain_or_cipher)]
    if variant == AUTOKEY_CIPHERTEXT:
        # 密钥流 = 密钥词 + 已生成的密文；这里由调用方传入密文作为尾部来源
        return (key + plain_or_cipher)[:len(plain_or_cipher)]
    raise ValueError(f"未知变体: {variant}")          # 非法变体直接报错


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------

def vigenere_encrypt(plain: str, key: str) -> str:
    """Vigenere 加密：密钥周期重复。"""
    plain = letters_only(plain)                       # 明文清洗成大写字母串
    key = letters_only(key)                           # 密钥同样清洗
    if not key:                                       # 空密钥无法构造密钥流
        raise ValueError("密钥不能为空")
    # zip 把明文与密钥流逐位配对,对每对做一次移位,拼成密文
    return "".join(_shift(p, k) for p, k in zip(plain, _build_keystream(plain, key, VIGENERE)))


def vigenere_decrypt(cipher: str, key: str) -> str:
    """Vigenere 解密。"""
    cipher = letters_only(cipher)                     # 密文清洗
    key = letters_only(key)                           # 密钥清洗
    if not key:
        raise ValueError("密钥不能为空")
    # 解密与加密对称,只是 _shift 传 decrypt=True(减法),密钥流构造完全相同
    return "".join(_shift(c, k, decrypt=True) for c, k in zip(cipher, _build_keystream(cipher, key, VIGENERE)))


def autokey_plaintext_encrypt(plain: str, key: str) -> str:
    """Autokey-明文 加密：keystream = 密钥 + 明文。"""
    plain = letters_only(plain)                       # 明文清洗
    key = letters_only(key)                           # 密钥清洗
    if not key:
        raise ValueError("密钥不能为空")
    ks = _build_keystream(plain, key, AUTOKEY_PLAINTEXT)  # 构造"密钥+明文"密钥流
    return "".join(_shift(p, k) for p, k in zip(plain, ks))  # 逐位移位得密文


def autokey_plaintext_decrypt(cipher: str, key: str) -> str:
    """Autokey-明文 解密：先恢复密钥词前缀，随后逐位用已解出的明文续密钥。"""
    cipher = letters_only(cipher)                     # 密文清洗
    key = letters_only(key)                           # 密钥清洗
    if not key:
        raise ValueError("密钥不能为空")
    out = []                                          # 存放逐位解出的明文
    for i, c in enumerate(cipher):                    # 逐位解密
        # 前 keylen 位密钥来自 key;之后第 i 位密钥 = 前面第 i-keylen 位已解出的明文
        k = key[i] if i < len(key) else out[i - len(key)]
        out.append(_shift(c, k, decrypt=True))        # 用该位密钥做减法移位解出明文
    return "".join(out)                               # 拼成明文


def autokey_ciphertext_encrypt(plain: str, key: str) -> str:
    """Autokey-密文 加密：keystream = 密钥 + 已生成密文。"""
    plain = letters_only(plain)                       # 明文清洗
    key = letters_only(key)                           # 密钥清洗
    if not key:
        raise ValueError("密钥不能为空")
    out = []                                          # 存放逐位生成的密文
    for i, p in enumerate(plain):                     # 逐位加密
        # 前 keylen 位密钥来自 key;之后第 i 位密钥 = 前面第 i-keylen 位刚生成的密文
        k = key[i] if i < len(key) else out[i - len(key)]
        out.append(_shift(p, k))                      # 用该位密钥做加法移位生成密文
    return "".join(out)                               # 拼成密文


def autokey_ciphertext_decrypt(cipher: str, key: str) -> str:
    """Autokey-密文 解密：密钥尾部直接取自已收到的密文。"""
    cipher = letters_only(cipher)                     # 密文清洗
    key = letters_only(key)                           # 密钥清洗
    if not key:
        raise ValueError("密钥不能为空")
    out = []                                          # 存放逐位解出的明文
    for i, c in enumerate(cipher):                    # 逐位解密
        # 前 keylen 位密钥来自 key;之后第 i 位密钥直接取密文 cipher[i-keylen]
        k = key[i] if i < len(key) else cipher[i - len(key)]
        out.append(_shift(c, k, decrypt=True))        # 减法移位解出明文
    return "".join(out)                               # 拼成明文


def encrypt(plain: str, key: str, variant: str = VIGENERE) -> str:
    """统一加密入口，按 variant 分派。"""
    if variant == VIGENERE:                           # 按变体字符串分派到对应加密函数
        return vigenere_encrypt(plain, key)
    if variant == AUTOKEY_PLAINTEXT:
        return autokey_plaintext_encrypt(plain, key)
    if variant == AUTOKEY_CIPHERTEXT:
        return autokey_ciphertext_encrypt(plain, key)
    raise ValueError(f"未知变体: {variant}")          # 未知变体报错


def decrypt(cipher: str, key: str, variant: str = VIGENERE) -> str:
    """统一解密入口，按 variant 分派。"""
    if variant == VIGENERE:                           # 按变体字符串分派到对应解密函数
        return vigenere_decrypt(cipher, key)
    if variant == AUTOKEY_PLAINTEXT:
        return autokey_plaintext_decrypt(cipher, key)
    if variant == AUTOKEY_CIPHERTEXT:
        return autokey_ciphertext_decrypt(cipher, key)
    raise ValueError(f"未知变体: {variant}")          # 未知变体报错


# ---------------------------------------------------------------------------
# 创新点：可审计轨迹 + 重合指数对比
# ---------------------------------------------------------------------------

def trace(plain: str, key: str, variant: str = VIGENERE) -> dict:
    """返回逐位对齐表（明文/密钥流/密文），便于写入报告并逐步验算。"""
    plain = letters_only(plain)                       # 明文清洗
    key = letters_only(key)                           # 密钥清洗
    if variant == VIGENERE:                           # 按变体构造密钥流
        ks = _build_keystream(plain, key, VIGENERE)
    elif variant == AUTOKEY_PLAINTEXT:
        ks = (key + plain)[:len(plain)]               # 明文自密钥:密钥+明文
    elif variant == AUTOKEY_CIPHERTEXT:
        cipher = autokey_ciphertext_encrypt(plain, key)  # 先算出密文
        ks = (key + cipher)[:len(plain)]              # 密文自密钥:密钥+密文
    else:
        raise ValueError(f"未知变体: {variant}")
    cipher = "".join(_shift(p, k) for p, k in zip(plain, ks))  # 用密钥流逐位加密
    return {"plain": plain, "keystream": ks, "cipher": cipher}  # 返回对齐表


def coincidence_index(text: str) -> float:
    """重合指数 IC = Σ n_i(n_i-1) / (N(N-1))，N 为字母总数。

    英文自然语言 IC≈0.0667，完全随机 IC≈0.0385。
    """
    text = letters_only(text)                         # 清洗成大写字母串
    n = len(text)                                     # 字母总数 N
    if n < 2:                                         # 样本太短,分母为 0 无意义,返回 0
        return 0.0
    freq = [text.count(ch) for ch in set(text)]       # 统计每个不同字母的出现次数
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))  # 套 IC 公式


def column_ic(text: str, period: int) -> float:
    """按给定周期把密文切成 period 列，返回各列 IC 的平均值（Friedman 检验）。

    若 period 恰为真实密钥长度，每列都是一次独立的 Caesar 移位，保留自然语言
    的字母分布，平均 IC 会明显高于其它周期——这就是定位 Vigenere 密钥长度的
    经典方法。Autokey 变体密钥不周期，故任何 period 都测不出明显峰值。
    """
    text = letters_only(text)                         # 清洗
    if period <= 0:                                   # 周期必须为正数
        raise ValueError("周期必须为正数")
    cols = [text[i::period] for i in range(period)]   # 从下标 i 起每隔 period 取一个,切成 period 列
    cols = [c for c in cols if len(c) >= 2]           # 太短的列不参与统计
    if not cols:                                      # 没有任何有效列则返回 0
        return 0.0
    return sum(coincidence_index(c) for c in cols) / len(cols)  # 各列 IC 求平均


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

def selftest() -> bool:
    ok = True                                          # 总开关

    def check(tag, got, want):                         # 局部断言辅助:比较并打印
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
    for variant in VARIANTS:                          # 遍历三种变体
        for p, k in [("Meet me at midnight", "SECRET"),  # 多组 (明文,密钥) 样例
                     ("The quick brown fox", "LEMON"),
                     ("Information security", "CRYPT")]:
            c = encrypt(p, k, variant)                # 统一入口加密
            back = decrypt(c, k, variant)             # 统一入口解密
            norm = letters_only(p)                    # 期望 = 清洗后的明文
            good = back == norm                       # 比较
            ok = ok and good
            print(f"  [{'PASS' if good else 'FAIL'}] {variant:20s} {k:6s} "
                  f"{norm:22s} -> {c}  还原={back}")

    print("列重合指数对照（创新点）:")
    # 用一段足够长的自然语言文本，比较“真实周期(5)”与“错误周期(4/6)”的列 IC。
    long_plain = letters_only(                        # 长文本(重复 3 遍)保证统计可靠
        "it was the best of times it was the worst of times "
        "it was the age of wisdom it was the age of foolishness " * 3)
    vc = encrypt(long_plain, "LEMON", VIGENERE)       # Vigenere 加密长文本
    print(f"  Vigenere 密文 列IC 周期4={column_ic(vc, 4):.4f}  "
          f"周期5={column_ic(vc, 5):.4f}  周期6={column_ic(vc, 6):.4f}   ← 周期5 出现峰值")
    ap = encrypt(long_plain, "LEMON", AUTOKEY_PLAINTEXT)   # Autokey-明文加密
    ac = encrypt(long_plain, "LEMON", AUTOKEY_CIPHERTEXT)  # Autokey-密文加密
    print(f"  Autokey-明文  列IC 周期4={column_ic(ap, 4):.4f}  "
          f"周期5={column_ic(ap, 5):.4f}  周期6={column_ic(ap, 6):.4f}")
    print(f"  Autokey-密文  列IC 周期4={column_ic(ac, 4):.4f}  "
          f"周期5={column_ic(ac, 5):.4f}  周期6={column_ic(ac, 6):.4f}")
    print("  （Autokey 两种变体无周期峰值，故 Friedman 检验失效）")

    print("自检通过 ✓" if ok else "自检失败 ✗")        # 打印总体结果
    return ok


# ---------------------------------------------------------------------------
# 交互入口
# ---------------------------------------------------------------------------

def interactive() -> None:
    print("=" * 50)                                   # 分隔线
    print("多表替代密码（Vigenere / Autokey）")
    print("=" * 50)
    key = input("输入密钥词: ").strip() or "LEMON"    # 读密钥词,空输入默认 LEMON
    plain = input("输入明文: ").strip() or "ATTACKATDAWN"  # 读明文,空输入默认样例
    for variant in VARIANTS:                          # 三种变体各演示一遍
        info = trace(plain, key, variant)             # 生成逐位对齐表
        print("-" * 50)
        print(f"变体      : {variant}")
        print(f"明文      : {info['plain']}")
        print(f"密钥流    : {info['keystream']}")
        print(f"密文      : {info['cipher']}")
        print(f"解密还原  : {decrypt(info['cipher'], key, variant)}")
        print(f"重合指数  : {coincidence_index(info['cipher']):.4f}")  # 附带打印密文 IC


def main() -> int:
    parser = argparse.ArgumentParser(description="多表替代密码（Vigenere / Autokey）")  # 命令行解析器
    parser.add_argument("-k", "--key", required=False, help="密钥词")
    parser.add_argument("-t", "--text", help="要处理的文本（明文或密文）")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt"],
                        default="encrypt", help="加密还是解密（默认 encrypt）")
    parser.add_argument("--variant", choices=VARIANTS, default=VIGENERE,
                        help="多表替代变体（默认 vigenere）")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()                        # 解析参数

    if args.selftest:                                 # 自检模式
        return 0 if selftest() else 1

    if args.key is not None and args.text is not None:  # 命令行数据模式:密钥和文本都给了
        try:
            result = (encrypt if args.mode == "encrypt" else decrypt)(  # 按模式选加密/解密
                args.text, args.key, args.variant)
        except ValueError as exc:                     # 捕获空密钥等错误
            print(f"错误: {exc}", file=sys.stderr)
            return 1
        print(f"变体      : {args.variant}")
        print(f"密钥词    : {args.key}")
        print(f"模式      : {args.mode}")
        print(f"输入      : {letters_only(args.text)}")
        print(f"输出      : {result}")
        return 0

    interactive()                                     # 无参数进入交互模式
    return 0


if __name__ == "__main__":
    sys.exit(main())                                  # 以 main() 返回值作为退出码
