#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SM2（国密椭圆曲线）C 实现桥接层 —— 把 sm2_cli 包装成框架统一公钥接口。

对齐 DH/cipher_registry.py 4.2 节公钥密码约定：
    generate() -> (private, public_str)
    encrypt(payload: bytes, public_str) -> bytes
    decrypt(ciphertext: bytes, private) -> bytes

编译（在 sm2_cli.c 所在目录执行）：
    gcc -Wall -Wextra -std=gnu99 -o sm2_cli sm2_cli.c sm2.c sm3.c bn.c

sm2_cli 还提供 bench / batch 模式：bench 用于单进程内循环计时，batch 用于后续
Python 以常驻子进程方式批量调用，避免每次加解密都重新启动进程。

格式约定（与 cipher_registry 里队友 Python 版保持一致，方便将来直接注册）：
- public_str = "十进制x:十进制y"（公钥点坐标，冒号分隔十进制整数）
- private    = int（私钥 d）
- 底层 C 侧 hex 进出，密文格式 C1x||C1y||C2||C3 = 64 + 明文长 + 32 字节
"""
import subprocess
import sys
from pathlib import Path

EXE = Path(__file__).resolve().parent / ("sm2_cli.exe" if sys.platform == "win32" else "sm2_cli")


def _run(args):
    try:
        r = subprocess.run([str(EXE), *args], capture_output=True, check=True)
    except FileNotFoundError:
        raise RuntimeError(
            f"未找到 C 可执行文件 {EXE}，请先编译："
            "gcc -Wall -Wextra -std=gnu99 -o sm2_cli sm2_cli.c sm2.c sm3.c bn.c") from None
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"sm2_cli 调用失败: {err or '（解密校验失败或参数错误）'}") from None
    return r.stdout.decode("utf-8").strip()


def generate():
    """生成密钥对：返回 (private: int, public_str: "十进制x:十进制y")。"""
    out = _run(["keygen"])
    fields = {}
    for line in out.splitlines():
        key, _, val = line.partition(" ")
        fields[key] = val.strip()
    if not (fields.get("d") and fields.get("Px") and fields.get("Py")):
        raise RuntimeError(f"keygen 输出格式异常: {out!r}")
    private = int(fields["d"], 16)
    public = f"{int(fields['Px'], 16)}:{int(fields['Py'], 16)}"
    return private, public


def encrypt(payload: bytes, public_str: str) -> bytes:
    """公钥加密：public_str 为 generate() 返回的格式，返回密文 bytes。"""
    try:
        x, y = (int(v) for v in public_str.split(":"))
    except ValueError:
        raise ValueError(f"公钥格式应为 '十进制x:十进制y'，收到: {public_str!r}") from None
    if not payload:
        raise ValueError("SM2 明文不能为空")
    out = _run(["enc", format(x, "x"), format(y, "x"), payload.hex()])
    return bytes.fromhex(out)


def decrypt(ciphertext: bytes, private: int) -> bytes:
    """私钥解密：private 为 generate() 返回的 int，返回明文 bytes。"""
    out = _run(["dec", format(private, "x"), ciphertext.hex()])
    return bytes.fromhex(out)


if __name__ == "__main__":
    # 独立自检：generate -> encrypt -> decrypt 往返
    priv, pub = generate()
    print(f"私钥 d = {priv}")
    print(f"公钥   = {pub}")
    for pt in (b"HELLO SM2", bytes(range(1, 100)), b"\x00\x01\x02\x03" * 50):
        ct = encrypt(pt, pub)
        assert decrypt(ct, priv) == pt, f"往返失败 len={len(pt)}"
        print(f"OK  往返 len={len(pt)}（密文 {len(ct)} 字节）")
    print("sm2_c 桥接层自检通过")
