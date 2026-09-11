#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密码算法适配层：把单机各密码模块统一成一致的 bytes 接口，供双机加解密调用。

统一接口约定（注册表里每个密码提供三项）：
- encrypt(payload: bytes, key: bytes) -> bytes   加密（明文字节 -> 密文字节）
- decrypt(cipher: bytes, key: bytes) -> bytes    解密（密文字节 -> 明文字节）
- make_key(key_str=None) -> bytes                生成/规范化演示密钥

不管底层算法是 bytes 型（AES/DES/RC4/CA）还是字符串型（古典密码），适配层
都归一化成 bytes 进出；密钥也统一成 bytes（古典密码的关键词编码成 UTF-8 字节）。
这样传输层信封里 key 与 payload 一律用 hex 字符串，无需为每种算法做特殊处理。

公钥密码（RSA/ECC/ElGamal/SM2）密钥流反向、MD5 单向散列，二者在阶段 B3 单独
处理，不在此注册表内（它们不是"同钥加解密"模型）。
"""
import hashlib          # 用 SHA-256 把任意字符串派生为定长字节密钥
import importlib.util   # 按文件路径动态加载各算法的 main.py 模块
import secrets          # 生成密码学安全的随机字节密钥
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent   # 当前文件所在目录（DH/ 或根目录）
ROOT = HERE.parent                       # 项目根目录，用于定位各算法子目录


def _load(name, path):
    # 动态加载一个指定路径下的 Python 文件为模块：
    # 1) 根据路径创建模块规范（ModuleSpec），不依赖 import 语句按名字找
    spec = importlib.util.spec_from_file_location(name, path)
    # 2) 用规范生成一个空模块对象
    mod = importlib.util.module_from_spec(spec)
    # 3) 先把模块塞进 sys.modules，这样模块内 dataclass 等解析类型注解时能按名找到自己
    sys.modules[name] = mod
    # 4) 真正执行文件里的代码，把函数/类定义填进 mod 的命名空间
    spec.loader.exec_module(mod)
    return mod          # 返回可用的模块对象


# 各密码模块都叫 main.py，这里用唯一模块名加载区分
# 每个 _load 调用：名字（注册进 sys.modules 的唯一标识）+ 该算法在仓库里的路径
AES = _load("cipher_aes", ROOT / "Block" / "AES" / "main.py")              # 加载 AES 模块
DES = _load("cipher_des", ROOT / "Block" / "DES" / "main.py")              # 加载 DES 模块
RC4 = _load("cipher_rc4", ROOT / "stream" / "RC4" / "main.py")             # 加载 RC4 模块
CA = _load("cipher_ca", ROOT / "stream" / "CA" / "main.py")                # 加载 CA 模块
MULTILITERAL = _load("cipher_multiliteral",                                # 加载单表替代 Multiliteral
                     ROOT / "ClassicalCiphers" / "MonoalphabeticSubstitution" / "MultiliteralCipher" / "main.py")
POLYALPHA = _load("cipher_polyalpha", ROOT / "ClassicalCiphers" / "PolyalphabeticSubstitution" / "main.py")   # 多表替代
TRANSPOSITION = _load("cipher_transposition", ROOT / "ClassicalCiphers" / "Transposition" / "main.py")         # 列置换
PLAYFAIR = _load("cipher_playfair", ROOT / "Playfair cipher" / "main.py")                                       # Playfair


# ---------------------------------------------------------------------------
# 适配器：把底层不一致的接口包成 bytes -> bytes
# ---------------------------------------------------------------------------

def _str_adapter(enc_fn, dec_fn):
    """把「str 进 str 出」的古典密码包成「bytes 进 bytes 出」（UTF-8 编解码）。"""
    def encrypt(payload, key):
        # 外部给的是 bytes，先解码成 str 交给底层算法，结果再编码回 bytes
        return enc_fn(payload.decode("utf-8"), key.decode("utf-8")).encode("utf-8")

    def decrypt(cipher, key):
        # 解密同理：bytes -> str -> 底层算法 -> str -> bytes
        return dec_fn(cipher.decode("utf-8"), key.decode("utf-8")).encode("utf-8")

    return encrypt, decrypt     # 返回包装后的 (加密, 解密) 二元组


def _transposition_adapter():
    """置换密码特殊：数据是 bytes、密钥是 str（列排序关键词）。"""
    def encrypt(payload, key):
        # 置换的数据本来就是 bytes，只有密钥需要从 bytes 解成 str 关键词
        return TRANSPOSITION.encrypt(payload, key.decode("utf-8"))

    def decrypt(cipher, key):
        # 解密同样只解密钥，数据 bytes 原样进出
        return TRANSPOSITION.decrypt(cipher, key.decode("utf-8"))

    return encrypt, decrypt     # 返回包装后的 (加密, 解密)


# ---------------------------------------------------------------------------
# 密钥规范化：让用户随意给一个字符串，也能得到符合各算法的密钥
# ---------------------------------------------------------------------------

def _bytes_key(n):
    """bytes 型密码：无 key 时随机生成；有 key 时用 SHA-256 派生出定长字节。"""
    def make(key_str=None):
        if key_str is None:
            return secrets.token_bytes(n)      # 没给密钥：直接随机生成 n 字节
        # 给了密钥：用 SHA-256 把任意长度字符串压成 32 字节摘要，取前 n 字节凑成定长密钥
        return hashlib.sha256(key_str.encode("utf-8")).digest()[:n]
    return make


def _str_key(default=b"LEMON"):
    """str 型密码：无 key 时用默认关键词；有 key 时直接编码成 UTF-8 字节。"""
    def make(key_str=None):
        return default if key_str is None else key_str.encode("utf-8")   # 默认词或 UTF-8 字节
    return make


# ---------------------------------------------------------------------------
# 注册表
# ---------------------------------------------------------------------------

def _entry(cipher_id, label, encrypt, decrypt, make_key):
    # 把一个算法打包成注册表条目：id、中文标签、加解密函数、密钥生成函数
    return {"id": cipher_id, "label": label,
            "encrypt": encrypt, "decrypt": decrypt, "make_key": make_key}


# 用适配器把各古典密码的原始接口包成统一的 bytes 接口
_ml_enc, _ml_dec = _str_adapter(MULTILITERAL.encrypt, MULTILITERAL.decrypt)   # Multiliteral 包装
_pa_enc, _pa_dec = _str_adapter(POLYALPHA.encrypt, POLYALPHA.decrypt)         # 多表替代包装
_pf_enc, _pf_dec = _str_adapter(PLAYFAIR.encrypt, PLAYFAIR.decrypt)           # Playfair 包装
_tr_enc, _tr_dec = _transposition_adapter()                                   # 列置换单独包装

REGISTRY = {
    # 键是算法 id，值是对应的注册条目；古典密码用关键词、现代密码用定长字节密钥
    "multiliteral":   _entry("multiliteral",   "单表替代 Multiliteral", _ml_enc, _ml_dec, _str_key(b"KEYWORD")),
    "vigenere":       _entry("vigenere",       "多表替代 Vigenere",     _pa_enc, _pa_dec, _str_key(b"LEMON")),
    "playfair":       _entry("playfair",       "多图替代 Playfair",     _pf_enc, _pf_dec, _str_key(b"PLAYFAIR")),
    "transposition":  _entry("transposition",  "置换（列置换）",         _tr_enc, _tr_dec, _str_key(b"ZEBRAS")),
    "rc4":            _entry("rc4",            "流密码 RC4",            RC4.rc4_crypt, RC4.rc4_crypt, _bytes_key(16)),  # RC4 加密解密同函数
    "ca":             _entry("ca",             "流密码 CA",             CA.ca_crypt,   CA.ca_crypt,   _bytes_key(16)),  # CA 加密解密同函数
    "des":            _entry("des",            "分块 DES",              DES.encrypt,   DES.decrypt,   _bytes_key(8)),   # DES 密钥 8 字节
    "aes":            _entry("aes",            "分块 AES-128",          AES.encrypt,   AES.decrypt,   _bytes_key(16)),  # AES-128 密钥 16 字节
}


def get(cipher_id):
    """按 id 取注册项，未知 id 抛出带可用列表的错误。"""
    if cipher_id not in REGISTRY:
        # 未知 id：报错并列出所有可用 id，方便调用方排查
        raise ValueError(f"未知密码: {cipher_id}，可选: {', '.join(REGISTRY)}")
    return REGISTRY[cipher_id]


def list_ciphers():
    """返回 [(id, label), ...]，供 CLI 展示。"""
    return [(cid, e["label"]) for cid, e in REGISTRY.items()]   # 提取每个条目的 id 和中文标签


# ---------------------------------------------------------------------------
# 公钥密码（阶段 B3）：密钥流反向 —— 解密端生成密钥对、发公钥，加密端用公钥加密
# ---------------------------------------------------------------------------

RSA = _load("cipher_rsa", ROOT / "publicKey" / "RSA" / "main.py")         # 加载 RSA 模块
ELGAMAL = _load("cipher_elgamal", ROOT / "publicKey" / "Elgamal" / "main.py")  # 加载 ElGamal
SM2 = _load("cipher_sm2", ROOT / "publicKey" / "SM2" / "main.py")         # 加载 SM2 模块
ECC = _load("cipher_ecc", ROOT / "publicKey" / "ECC" / "main.py")         # 加载 ECC 模块
MD5 = _load("cipher_md5", ROOT / "MD5" / "main.py")                       # 加载 MD5 模块

RSA_BITS = 512        # 演示用；生产应 ≥ 2048
ELGAMAL_BITS = 128    # 演示用（安全素数生成较慢，取小）；生产应 ≥ 2048


def _rsa_generate():
    key = RSA.generate_key(bits=RSA_BITS)              # 生成 RSA 密钥对
    return key.private, f"{key.n}:{key.e}"             # 返回 (私钥, "n:e" 形式的公钥字符串)


def _rsa_encrypt(payload, pub_str):
    n, e = (int(x) for x in pub_str.split(":"))        # 把 "n:e" 公钥字符串拆成两个大整数
    m = int.from_bytes(payload, "big")                 # 明文 bytes 转成一个大整数（大端）
    if not (0 <= m < n):                               # 裸 RSA 要求明文整数必须小于模数 n
        raise ValueError("明文过大，超过 RSA 模数 n（裸 RSA 无填充，只适合短消息）")
    c = RSA.encrypt(m, (n, e))                         # 密文 c = m^e mod n
    return c.to_bytes((n.bit_length() + 7) // 8, "big")  # 密文整数按 n 的字节宽度转回 bytes


def _rsa_decrypt(ct, private):
    n, d = private                                     # 私钥拆成 (模数 n, 私钥指数 d)
    m = RSA.decrypt(int.from_bytes(ct, "big"), (n, d)) # 明文 m = c^d mod n
    return m.to_bytes((m.bit_length() + 7) // 8, "big")  # 明文整数转回 bytes


def _elgamal_generate():
    key = ELGAMAL.generate_key(bits=ELGAMAL_BITS)      # 生成 ElGamal 密钥对
    return key, f"{key.p}:{key.g}:{key.y}"             # 返回 (密钥对象, "p:g:y" 公钥字符串)


def _elgamal_encrypt(payload, pub_str):
    p, g, y = (int(x) for x in pub_str.split(":"))     # 公钥字符串拆成 (p, g, y) 三个大整数
    m = int.from_bytes(payload, "big")                 # 明文 bytes 转大整数
    if not (1 <= m < p):                               # ElGamal 明文整数须在 [1, p) 区间
        raise ValueError("明文过大，超过 ElGamal 模数 p（裸 ElGamal 只适合短消息）")
    c1, c2 = ELGAMAL.encrypt(m, (p, g, y))             # 密文对 (c1, c2)
    w = (p.bit_length() + 7) // 8                      # 每个密文分量的字节宽度
    return c1.to_bytes(w, "big") + c2.to_bytes(w, "big")  # 两个分量各按固定宽度拼成 bytes


def _elgamal_decrypt(ct, key):
    w = (key.p.bit_length() + 7) // 8                  # 每个分量的字节宽度（与加密一致）
    c1 = int.from_bytes(ct[:w], "big")                 # 前半段是 c1
    c2 = int.from_bytes(ct[w:], "big")                 # 后半段是 c2
    m = ELGAMAL.decrypt((c1, c2), key)                 # 用私钥解出明文整数
    return m.to_bytes((m.bit_length() + 7) // 8, "big")  # 明文整数转回 bytes


def _sm2_generate():
    d, pub = SM2.generate_keypair()                    # 生成 SM2 密钥对（私钥 d + 公钥点 pub）
    return d, f"{pub[0]}:{pub[1]}"                     # 公钥点 (x, y) 序列化成 "x:y" 字符串


def _sm2_encrypt(payload, pub_str):
    x, y = (int(v) for v in pub_str.split(":"))        # 公钥点字符串拆成两个整数坐标
    return SM2.encrypt_pke(payload, (x, y))            # 调用 SM2 公钥加密（PKE 模式）


def _sm2_decrypt(ct, d):
    return SM2.decrypt_pke(ct, d)                      # 调用 SM2 私钥解密


def _pubkey_entry(cipher_id, label, generate, encrypt, decrypt):
    # 打包公钥密码条目：额外带 generate（生成密钥对），与对称注册表结构不同
    return {"id": cipher_id, "label": label,
            "generate": generate, "encrypt": encrypt, "decrypt": decrypt}


PUBKEY_REGISTRY = {
    # 公钥密码注册表：每个条目提供 generate/encrypt/decrypt 三项
    "rsa":     _pubkey_entry("rsa",     "公钥 RSA",     _rsa_generate,     _rsa_encrypt,     _rsa_decrypt),
    "elgamal": _pubkey_entry("elgamal", "公钥 ElGamal", _elgamal_generate, _elgamal_encrypt, _elgamal_decrypt),
    "sm2":     _pubkey_entry("sm2",     "公钥 SM2",     _sm2_generate,     _sm2_encrypt,     _sm2_decrypt),
}


def get_pubkey(cipher_id):
    if cipher_id not in PUBKEY_REGISTRY:
        # 未知公钥密码 id：报错并列出可用项
        raise ValueError(f"未知公钥密码: {cipher_id}，可选: {', '.join(PUBKEY_REGISTRY)}")
    return PUBKEY_REGISTRY[cipher_id]


def list_pubkey_ciphers():
    return [(cid, e["label"]) for cid, e in PUBKEY_REGISTRY.items()]   # 提取公钥密码 id 和标签


# ---------------------------------------------------------------------------
# MD5（单向散列）与 ECC（ECDH 密钥交换）
# ---------------------------------------------------------------------------

def md5_hex(payload):
    """计算 MD5 十六进制摘要，双机场景用于完整性校验。"""
    return MD5.md5_hex(payload)    # 直接转发给 MD5 模块


_ECC_CURVE = ECC.SECP256K1          # 固定使用 secp256k1 曲线


def ecc_generate_keypair():
    """生成 ECC(secp256k1) 密钥对，返回 (私钥 d, 公钥点 Q)。"""
    return ECC.generate_keypair(_ECC_CURVE)    # 在选定曲线上生成密钥对


def ecc_ecdh(priv, peer_pub):
    """计算 ECDH 共享点 S = priv · peer_pub。"""
    return ECC.ecdh(priv, peer_pub, _ECC_CURVE)  # 自己的私钥 × 对方公钥 = 共享密钥点


def ecc_point_serialize(p):
    """把椭圆曲线点序列化成 "x:y" 十六进制字符串。"""
    return f"{p[0]:x}:{p[1]:x}"    # 两个坐标分别转十六进制，用冒号连接


def ecc_point_parse(s):
    """从 "x:y" 十六进制字符串还原椭圆曲线点。"""
    x, y = s.split(":")            # 按冒号切开两个十六进制串
    return int(x, 16), int(y, 16)  # 各按 16 进制转回整数坐标
