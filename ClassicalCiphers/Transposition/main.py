"""列置换密码（Columnar Transposition Cipher）实验。

创新点：采用“变长列布局”。普通实现常用 X 补齐矩阵，本实现不填充伪字符，
根据明文长度计算每列真实长度，再按列编号读取，因此中文、标点和文件字节都能
无损恢复；trace() 还能输出矩阵布局和读取顺序，便于检查每一步是否正确。
仅使用 Python 标准库，不调用现成密码库。
"""
from pathlib import Path


def column_order(key):
    """返回按字母序读取列的下标；相同字符按原位置稳定排序。"""
    if not key:
        raise ValueError("密钥不能为空")
    if len(set(key)) != len(key):
        raise ValueError("为避免列编号歧义，密钥不能包含重复字符")
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def column_lengths(data_length, width):
    """计算不补齐矩阵时每一列真实拥有的字节数。"""
    if width <= 0:
        raise ValueError("列数必须为正数")
    full_rows, remainder = divmod(data_length, width)
    return [full_rows + (1 if col < remainder else 0) for col in range(width)]


def encrypt(data, key):
    """按行写入矩阵，再按密钥排序后的列顺序读取。"""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    order = column_order(key)
    width = len(key)
    lengths = column_lengths(len(raw), width)
    return b"".join(raw[col::width][:lengths[col]] for col in order)


def decrypt(ciphertext, key):
    """按列顺序分配密文，再按原矩阵行顺序重建明文。"""
    cipher = ciphertext.encode("utf-8") if isinstance(ciphertext, str) else bytes(ciphertext)
    width = len(key)
    order = column_order(key)
    lengths = column_lengths(len(cipher), width)
    columns = [b""] * width
    cursor = 0
    for col in order:
        size = lengths[col]
        columns[col] = cipher[cursor:cursor + size]
        cursor += size
    return b"".join(columns[col][row:row + 1] for row in range(max(lengths, default=0)) for col in range(width) if row < len(columns[col]))


def trace(data, key):
    """返回矩阵、列编号和密文读取顺序，作为可审计实验记录。"""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    width = len(key)
    order = column_order(key)
    rows = [list(raw[i:i + width]) for i in range(0, len(raw), width)]
    return {
        "key": key,
        "column_numbers": list(range(1, width + 1)),
        "read_order": [i + 1 for i in order],
        "matrix_rows": [[x.decode("utf-8", errors="replace") if isinstance(x, bytes) else chr(x) for x in row] for row in rows],
        "ciphertext_hex": encrypt(raw, key).hex(),
    }


def encrypt_file(input_path, output_path, key):
    Path(output_path).write_bytes(encrypt(Path(input_path).read_bytes(), key))


def decrypt_file(input_path, output_path, key):
    Path(output_path).write_bytes(decrypt(Path(input_path).read_bytes(), key))


def main():
    key = "ZEBRAS"
    plaintext = "WE ARE DISCOVERED. FLEE AT ONCE"
    ciphertext = encrypt(plaintext, key)
    print("列置换密码实验")
    print("密钥:", key)
    print("明文:", plaintext)
    print("密文:", ciphertext.decode("utf-8"))
    print("解密:", decrypt(ciphertext, key).decode("utf-8"))
    print("创新-变长列布局轨迹:")
    info = trace(plaintext, key)
    print("列读取顺序:", info["read_order"])
    print("矩阵:", info["matrix_rows"])
    print("密文十六进制:", info["ciphertext_hex"])
    if Path("input.txt").exists():
        encrypt_file("input.txt", "output.trans", key)
        decrypt_file("output.trans", "restored.txt", key)
        print("文件回环:", "PASS" if Path("restored.txt").read_bytes() == Path("input.txt").read_bytes() else "FAIL")


if __name__ == "__main__":
    main()
