"""
小规模 Diffie-Hellman 密钥交换实验

创新点：把一次交换变成“可审计交换记录”。程序记录双方公开值、共享密钥摘要，
并用共享密钥派生 AES/DES 实验密钥；同时模拟公开值被篡改后的结果，直观看到
双方密钥不一致。这里没有调用密码学库，快速模幂也由本文件手写完成。
"""
from hashlib import sha256
from hmac import new as hmac_new


def fast_pow(base, exponent, modulus, trace=False):
    """右到左二进制快速模幂，并可返回每一步的 (指数,当前底数,结果)。"""
    if modulus <= 1 or exponent < 0:
        raise ValueError("模数必须大于1，指数不能为负数")
    base %= modulus
    result = 1
    steps = []
    while exponent:
        if trace:
            steps.append((exponent, base, result))
        if exponent & 1:
            result = result * base % modulus
        base = base * base % modulus
        exponent >>= 1
    return (result, steps) if trace else result


def validate_parameters(prime, generator):
    if prime <= 3:
        raise ValueError("素数参数过小")
    if not 1 < generator < prime:
        raise ValueError("生成元必须满足 1 < g < p")


def public_value(private_key, prime, generator):
    if private_key <= 1 or private_key >= prime - 1:
        raise ValueError("私有值应位于 2 到 p-2 之间")
    return fast_pow(generator, private_key, prime)


def shared_secret(peer_public, private_key, prime):
    if not 1 < peer_public < prime:
        raise ValueError("收到的公开值不在合法范围内")
    return fast_pow(peer_public, private_key, prime)


def derive_key(secret, label, length=16):
    """用 HMAC-SHA256 做简单、可复现的密钥派生，避免直接截取共享整数。"""
    if length <= 0:
        raise ValueError("派生长度必须为正数")
    seed = secret.to_bytes((secret.bit_length() + 7) // 8 or 1, "big")
    output = bytearray()
    counter = 1
    while len(output) < length:
        output.extend(hmac_new(seed, label.encode() + bytes([counter]), sha256).digest())
        counter += 1
    return bytes(output[:length])


def exchange(prime=7919, generator=5, alice_private=1234, bob_private=5678):
    """执行一次完整交换，返回可写入报告的结构化记录。"""
    validate_parameters(prime, generator)
    alice_public = public_value(alice_private, prime, generator)
    bob_public = public_value(bob_private, prime, generator)
    alice_secret = shared_secret(bob_public, alice_private, prime)
    bob_secret = shared_secret(alice_public, bob_private, prime)
    return {
        "p": prime, "g": generator,
        "alice_private": alice_private, "bob_private": bob_private,
        "alice_public": alice_public, "bob_public": bob_public,
        "alice_secret": alice_secret, "bob_secret": bob_secret,
        "same_secret": alice_secret == bob_secret,
        "secret_sha256": sha256(str(alice_secret).encode()).hexdigest(),
        "aes_key": derive_key(alice_secret, "AES-128", 16).hex(),
        "des_key": derive_key(alice_secret, "DES-64", 8).hex(),
    }


def tamper_demo(record):
    """将 Bob 收到的 Alice 公开值改动一位，观察共享结果是否仍一致。"""
    fake_public = record["alice_public"] ^ 1
    fake_bob_secret = shared_secret(fake_public, record["bob_private"], record["p"])
    return fake_public, fake_bob_secret, fake_bob_secret == record["alice_secret"]


def main():
    record = exchange()
    print("DH 密钥交换实验")
    print(f"公共参数: p={record['p']}, g={record['g']}")
    print(f"Alice: 私有值={record['alice_private']}, 公开值={record['alice_public']}")
    print(f"Bob:   私有值={record['bob_private']}, 公开值={record['bob_public']}")
    print(f"Alice 共享密钥={record['alice_secret']}")
    print(f"Bob   共享密钥={record['bob_secret']}")
    print("共享密钥一致:", "PASS" if record["same_secret"] else "FAIL")
    print("共享密钥 SHA-256:", record["secret_sha256"])
    print("派生 AES-128 密钥:", record["aes_key"])
    print("派生 DES-64 密钥:", record["des_key"])

    fake_public, fake_secret, same = tamper_demo(record)
    print("创新-公开值篡改实验:")
    print(f"篡改后的 Alice 公开值={fake_public}")
    print(f"Bob 重新计算的共享密钥={fake_secret}")
    print("篡改后仍一致:", "YES" if same else "NO（检测到交换结果变化）")

    _, trace = fast_pow(record["g"], record["alice_private"], record["p"], trace=True)
    print("快速模幂步骤数:", len(trace))


if __name__ == "__main__":
    main()
