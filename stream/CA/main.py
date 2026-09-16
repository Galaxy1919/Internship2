#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CA(元胞自动机)流密码实现

原理
CA是一维格子,每个格子(细胞)只有 0/1两种状态,按规则同步更新:新状态只取决于它自己和左右邻居的旧状态。
  ... [L] [C] [R] ...  ->  C' = f(L, C, R)
规则编号是把 8 种邻居组合(111,110,...,000)对应的输出拼成一个8 位二进制数,再转十进制。例如 Rule 30:

LCR: 111 110 101 100 011 010 001 000
新状态:0   0   0   1   1   1   1   0     -> 二进制 00011110 = 30

运行
python main.py                       # 交互模式
python main.py -k 密钥 -t 明文        # 命令行模式
python main.py -k 密钥 -t 明文 --rule 110   # 自定义规则
python main.py --selftest            # 往返/确定性自检
"""

import argparse
import hashlib
import sys

DEFAULT_CELLS = 64    # 细胞个数(每轮产出 64 / 8 = 8 字节密钥流)
DEFAULT_RULE = 30     # 默认演化规则
WARMUP_STEPS = 100    # 预热轮数,消除初始状态的相关性

def build_rule_table(rule: int) -> list:
    """把规则编号展开成查表。

    rule 的 8 个二进制位,从高位到低位依次对应邻居组合
    111, 110, 101, ..., 000 的输出。
    """
    return [(rule >> (7 - i)) & 1 for i in range(8)]


def key_to_seed_cells(key: bytes, cells: int = DEFAULT_CELLS) -> list:
    # 把手工输入的密钥sha256一下，保证随机和位数
    seed = hashlib.sha256(key).digest()# 字节串，sha256的32个字节相当于seed是32位的数组
    bits = []
    for b in seed:
        for shift in range(7, -1, -1):# 每个字节从高位到低位取
            bits.append((b >> shift) & 1)
    return [bits[i % len(bits)] for i in range(cells)]# bits共256位，而i只能到cell的64位，剩下的都丢弃了


def ca_step(cells: list, table: list) -> list:
    # 演化一轮:每个细胞的新状态 = f(左邻居, 自己, 右邻居)环形。
    n = len(cells)
    new = [0] * n
    for i in range(n):
        left = cells[(i - 1) % n]
        center = cells[i]
        right = cells[(i + 1) % n]
        idx = (left << 2) | (center << 1) | right   # 即left center right拼接为三位二进制，对应邻居组合 -> 0..7
        new[i] = table[idx]
    return new


def ca_keystream(key: bytes,
                 n_bytes: int,
                 rule: int = DEFAULT_RULE,
                 cells: int = DEFAULT_CELLS,
                 warmup: int = WARMUP_STEPS) -> bytes:
    """由密钥生成 n_bytes 字节密钥流。
    流程:密钥 -> 初始细胞 -> 预热 -> 循环演化并拼字节 -> 截断到所需长度。
    """
    table = build_rule_table(rule)
    state = key_to_seed_cells(key, cells)

    for _ in range(warmup):
        state = ca_step(state, table)
    
    keystream = bytearray()
    # 遍历当前 64 个细胞，把每个 bit 左移拼进 byte_val；每拼满 8 个 bit，就追加一个字节到 keystream。
    while len(keystream) < n_bytes:
        state = ca_step(state, table)
        byte_val = 0
        for i in range(cells):
            byte_val = (byte_val << 1) | state[i]
            if i % 8 == 7:
                keystream.append(byte_val)
                byte_val = 0
    return bytes(keystream[:n_bytes])


# --------------------------------------------
# 优化: 位并行 (bitwise parallel) 版本
# --------------------------------------------
# 思路: 把 n 个 cell 打包进一个 Python 大整数,
#   约定 "cell[i] 位于该整数的 bit (n-1-i)",也就是 cell[0] 是最高位、
#   cell[n-1] 是最低位。这与原实现拼字节时 (byte_val<<1)|state[i]
#   的高位在前顺序完全一致,便于 state.to_bytes 直接落盘。
#
# 一步演化只需两次移位构造左右邻居 + 至多 8 次位与/或,即可在一个大整数上
# 同时算出所有 n 个 cell 的新状态,把 Python 内层 for 循环彻底消掉。
#
# 出字节同样绕开逐位拼装: state.to_bytes(n//8, 'big') 一次成型 (即优化3)。

def _rule_masks(rule: int, full_mask: int) -> tuple:
    """把规则拆成邻居模式索引, 与原 build_rule_table 保持完全一致的语义:
    原实现里 table[idx] = (rule >> (7-idx)) & 1, 也就是 pattern p (0..7)
    对应 rule 的 bit (7-p)。这里沿用同一约定, 只保留输出为 1 的 pattern,
    返回 [(need_L, need_C, need_R), ...] 供位并行组合使用。
    """
    triggers = []
    for p in range(8):
        if (rule >> (7 - p)) & 1:
            triggers.append(((p >> 2) & 1, (p >> 1) & 1, p & 1))
    return triggers


def ca_step_bitparallel(state: int, rule: int, n: int,
                        full_mask: int, triggers: list) -> int:
    """位并行一步演化。state 是打包好的 n-bit 整数, 返回新的 n-bit 整数。"""
    # 环形左右邻居: 沿 bit 位方向的"左邻"其实是 bit 更高一位, "右邻"是更低一位。
    # 因为 cell[i] 在 bit (n-1-i), cell[i-1] 在 bit (n-i), 比自己高一位。
    #   → 邻居"左" L 通过 state 右移 1 得到,并把最低位环绕到最高位;
    #   → 邻居"右" R 通过 state 左移 1 得到,并把最高位环绕到最低位。
    hi_bit = 1 << (n - 1)
    L = ((state >> 1) | ((state & 1) << (n - 1))) & full_mask
    R = ((state << 1) & full_mask) | ((state & hi_bit) >> (n - 1))
    C = state

    # 对每一个 rule 中为 1 的邻居模式,用位与筛出所有匹配位置,再或进结果
    result = 0
    for need_l, need_c, need_r in triggers:
        ml = L if need_l else (L ^ full_mask)      # ~L 但保持在 n 位内
        mc = C if need_c else (C ^ full_mask)
        mr = R if need_r else (R ^ full_mask)
        result |= ml & mc & mr
    return result & full_mask


def _pack_bits(bits: list) -> int:
    """把 [b0, b1, ..., b_{n-1}] 打包成整数, b0 在最高位。"""
    v = 0
    for b in bits:
        v = (v << 1) | (b & 1)
    return v


def ca_keystream_fast(key: bytes,
                      n_bytes: int,
                      rule: int = DEFAULT_RULE,
                      cells: int = DEFAULT_CELLS,
                      warmup: int = WARMUP_STEPS) -> bytes:
    """位并行 + 整块出字节。语义与 ca_keystream 完全一致。"""
    if cells % 8 != 0:
        # 出字节要求整字节,不整除时退回原实现以保证正确性
        return ca_keystream(key, n_bytes, rule=rule, cells=cells, warmup=warmup)

    full_mask = (1 << cells) - 1
    triggers = _rule_masks(rule, full_mask)
    state = _pack_bits(key_to_seed_cells(key, cells))

    for _ in range(warmup):
        state = ca_step_bitparallel(state, rule, cells, full_mask, triggers)

    step_bytes = cells // 8
    keystream = bytearray()
    while len(keystream) < n_bytes:
        state = ca_step_bitparallel(state, rule, cells, full_mask, triggers)
        keystream += state.to_bytes(step_bytes, "big")
    return bytes(keystream[:n_bytes])


def ca_crypt(data: bytes, key: bytes, rule: int = DEFAULT_RULE) -> bytes:
    """加密与解密是同一个操作:数据与密钥流逐字节异或。默认走位并行快速路径。"""
    # 明文⊕密钥流=密文，密文⊕密钥流=明文
    keystream = ca_keystream_fast(key, len(data), rule=rule)
    return bytes(a ^ b for a, b in zip(data, keystream))

# 测试

def selftest() -> bool:
    """自检三个性质:
    1. 加解密往返一致(解密能把密文还原成明文)
    2. 确定性:同一密钥两次生成同一密钥流
    3. 区分度:不同密钥生成的密钥流不同(随机性下限)
    """
    key1 = b"ca-demo-key"
    key2 = b"ca-demo-Key"
    plain = "元胞自动机流密码测试 0123456789".encode("utf-8")

    cipher = ca_crypt(plain, key1)
    back = ca_crypt(cipher, key1)
    round_ok = back == plain

    ks1a = ca_keystream(key1, 64)
    ks1b = ca_keystream(key1, 64)
    deter_ok = ks1a == ks1b

    ks2 = ca_keystream(key2, 64)
    diff_ok = ks1a != ks2

    # 位并行版本必须与原实现产出完全一致 (覆盖多条规则)
    import time as _t
    parity_ok = True
    for rule in (30, 90, 110, 150, 45, 0, 255):
        a = ca_keystream(key1, 256, rule=rule)
        b = ca_keystream_fast(key1, 256, rule=rule)
        if a != b:
            parity_ok = False
            print(f"  规则 {rule} 下位并行结果与原实现不一致!")
            break

    # 简单基准: 生成 8KB 密钥流, 对比两条路径
    N = 8192
    t0 = _t.perf_counter()
    ca_keystream(key1, N)
    t_slow = _t.perf_counter() - t0
    t0 = _t.perf_counter()
    ca_keystream_fast(key1, N)
    t_fast = _t.perf_counter() - t0
    speedup = t_slow / t_fast if t_fast > 0 else float("inf")

    print("CA 流密码自检:")
    print(f"加解密往返一致      : {'PASS' if round_ok else 'FAIL'}")
    print(f"同密钥密钥流确定    : {'PASS' if deter_ok else 'FAIL'}")
    print(f"不同密钥密钥流不同  : {'PASS' if diff_ok else 'FAIL'}")
    print(f"位并行与原实现等价  : {'PASS' if parity_ok else 'FAIL'}")
    print(f"基准({N} 字节)      : 原={t_slow*1000:.1f}ms  快速={t_fast*1000:.1f}ms  "
          f"加速 x{speedup:.1f}")

    ok = round_ok and deter_ok and diff_ok and parity_ok
    print("自检通过 ✓" if ok else "自检失败 ✗")
    return ok

# 交互入口

def interactive(rule: int = DEFAULT_RULE) -> None:
    print(f"CA演示，Rule= {rule}")
    key_text = input("输入密钥: ").strip() or "default"
    plain_text = input("输入明文: ").strip() or "Hello CA"
    if not key_text:
        print("密钥不能为空!")
        return
    key = key_text.encode("utf-8")
    plain = plain_text.encode("utf-8")

    cipher = ca_crypt(plain, key, rule=rule)
    back = ca_crypt(cipher, key, rule=rule)

    print(f"密钥      : {key_text}")
    print(f"明文      : {plain_text}")
    print(f"密文(hex) : {cipher.hex().upper()}")
    print(f"解密还原  : {back.decode('utf-8')}")

def main() -> int:
    parser = argparse.ArgumentParser(description="CA流密码")
    parser.add_argument("-k", "--key", help="密钥字符串")
    parser.add_argument("-t", "--text", help="明文/密文字符串")
    parser.add_argument("--rule", type=int, default=DEFAULT_RULE,
                        help=f"演化规则编号(默认 {DEFAULT_RULE})")
    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.selftest:
        return 0 if selftest() else 1
    if args.key is not None and args.text is not None:
        if not args.key:
            print("密钥不能为空!")
            return 1
        key = args.key.encode("utf-8")
        data = args.text.encode("utf-8")
        cipher = ca_crypt(data, key, rule=args.rule)
        back = ca_crypt(cipher, key, rule=args.rule)
        print(f"密钥      : {args.key}")
        print(f"明文      : {args.text}")
        print(f"密文(hex) : {cipher.hex().upper()}")
        print(f"解密还原  : {back.decode('utf-8')}")
        return 0
    interactive(rule=args.rule)
    return 0


if __name__ == "__main__":
    sys.exit(main())
