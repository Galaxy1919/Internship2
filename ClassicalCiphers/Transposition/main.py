"""列置换密码（Columnar Transposition Cipher）实验。

创新点：采用“变长列布局”。普通实现常用 X 补齐矩阵，本实现不填充伪字符，
根据明文长度计算每列真实长度，再按列编号读取，因此中文、标点和文件字节都能
无损恢复；trace() 还能输出矩阵布局和读取顺序，便于检查每一步是否正确。
仅使用 Python 标准库，不调用现成密码库。
"""
from pathlib import Path


def column_order(key):
    """返回按字母序读取列的下标；相同字符按原位置稳定排序。"""
    if not key:                                     # 空密钥无法确定列序
        raise ValueError("密钥不能为空")
    if len(set(key)) != len(key):                   # 有重复字符则列编号有歧义,拒绝
        raise ValueError("为避免列编号歧义，密钥不能包含重复字符")
    # 对列下标 0..len-1 排序,排序键是 (该列字母, 原下标):字母小的列先读,同字母按原位置
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def column_lengths(data_length, width):
    """计算不补齐矩阵时每一列真实拥有的字节数。"""
    if width <= 0:                                  # 列数必须为正
        raise ValueError("列数必须为正数")
    full_rows, remainder = divmod(data_length, width)  # 整除得完整行数,余数是"多一行的列数"
    # 前 remainder 列比其余列多 1 个字节(最后一行只填到第 remainder 列为止)
    return [full_rows + (1 if col < remainder else 0) for col in range(width)]


def encrypt(data, key):
    """按行写入矩阵，再按密钥排序后的列顺序读取。"""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)  # 统一转 bytes(支持中文/文件)
    order = column_order(key)                       # 计算读取列顺序
    width = len(key)                                # 列数 = 密钥长度
    lengths = column_lengths(len(raw), width)       # 每列真实字节数
    # 按 order 指定的列序,对每列取 raw[col::width](该列元素),再截到真实长度,拼成密文
    return b"".join(raw[col::width][:lengths[col]] for col in order)


def decrypt(ciphertext, key):
    """按列顺序分配密文，再按原矩阵行顺序重建明文。"""
    cipher = ciphertext.encode("utf-8") if isinstance(ciphertext, str) else bytes(ciphertext)  # 统一转 bytes
    width = len(key)                                # 列数
    order = column_order(key)                       # 读取列顺序(与加密一致)
    lengths = column_lengths(len(cipher), width)    # 各列真实长度(与加密一致)
    columns = [b""] * width                         # 初始化 width 个空列
    cursor = 0                                      # 游标指向密文当前切分位置
    for col in order:                               # 按读取顺序把密文切回各列
        size = lengths[col]                         # 当前这一列的字节数
        columns[col] = cipher[cursor:cursor + size] # 从密文切出这一列
        cursor += size                              # 游标前进
    # 按"行优先"重建:外层遍历行号(0..最大行长),内层遍历列号,跳过某列已无该行的格子
    return b"".join(columns[col][row:row + 1] for row in range(max(lengths, default=0)) for col in range(width) if row < len(columns[col]))


def trace(data, key):
    """返回矩阵、列编号和密文读取顺序，作为可审计实验记录。"""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)  # 统一转 bytes
    width = len(key)                                # 列数
    order = column_order(key)                       # 读取顺序
    rows = [list(raw[i:i + width]) for i in range(0, len(raw), width)]  # 按行切块,组成矩阵
    return {
        "key": key,                                 # 密钥
        "column_numbers": list(range(1, width + 1)),  # 列编号 1..width
        "read_order": [i + 1 for i in order],       # 读取顺序(转 1-based)
        # 矩阵每一格:bytes 尝试解 UTF-8,失败则用 chr 显示字节值
        "matrix_rows": [[x.decode("utf-8", errors="replace") if isinstance(x, bytes) else chr(x) for x in row] for row in rows],
        "ciphertext_hex": encrypt(raw, key).hex(),  # 密文的十六进制形式
    }


def encrypt_file(input_path, output_path, key):
    # 文件加密:读入 bytes -> 加密 -> 写出
    Path(output_path).write_bytes(encrypt(Path(input_path).read_bytes(), key))


def decrypt_file(input_path, output_path, key):
    # 文件解密:读入 bytes -> 解密 -> 写出
    Path(output_path).write_bytes(decrypt(Path(input_path).read_bytes(), key))


def main():
    key = "ZEBRAS"                                  # 演示密钥
    plaintext = "WE ARE DISCOVERED. FLEE AT ONCE"   # 演示明文(含空格和标点)
    ciphertext = encrypt(plaintext, key)            # 加密
    print("列置换密码实验")
    print("密钥:", key)
    print("明文:", plaintext)
    print("密文:", ciphertext.decode("utf-8"))      # 密文 bytes 解回字符串显示
    print("解密:", decrypt(ciphertext, key).decode("utf-8"))  # 解密回环
    print("创新-变长列布局轨迹:")
    info = trace(plaintext, key)                    # 生成轨迹
    print("列读取顺序:", info["read_order"])
    print("矩阵:", info["matrix_rows"])
    print("密文十六进制:", info["ciphertext_hex"])
    if Path("input.txt").exists():                  # 若存在 input.txt 则做文件回环测试
        encrypt_file("input.txt", "output.trans", key)
        decrypt_file("output.trans", "restored.txt", key)
        print("文件回环:", "PASS" if Path("restored.txt").read_bytes() == Path("input.txt").read_bytes() else "FAIL")


if __name__ == "__main__":
    main()
