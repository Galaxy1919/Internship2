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
import hashlib
import importlib.util
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# 各密码模块都叫 main.py，这里用唯一模块名加载区分
AES = _load("cipher_aes", ROOT / "Block" / "AES" / "main.py")
DES = _load("cipher_des", ROOT / "Block" / "DES" / "main.py")
RC4 = _load("cipher_rc4", ROOT / "stream" / "RC4" / "main.py")
CA = _load("cipher_ca", ROOT / "stream" / "CA" / "main.py")
MULTILITERAL = _load("cipher_multiliteral",
                     ROOT / "ClassicalCiphers" / "MonoalphabeticSubstitution" / "MultiliteralCipher" / "main.py")
POLYALPHA = _load("cipher_polyalpha", ROOT / "ClassicalCiphers" / "PolyalphabeticSubstitution" / "main.py")
TRANSPOSITION = _load("cipher_transposition", ROOT / "ClassicalCiphers" / "Transposition" / "main.py")
PLAYFAIR = _load("cipher_playfair", ROOT / "Playfair cipher" / "main.py")


# ---------------------------------------------------------------------------
# 适配器：把底层不一致的接口包成 bytes -> bytes
# ---------------------------------------------------------------------------

def _str_adapter(enc_fn, dec_fn):
    """把「str 进 str 出」的古典密码包成「bytes 进 bytes 出」（UTF-8 编解码）。"""
    def encrypt(payload, key):
        return enc_fn(payload.decode("utf-8"), key.decode("utf-8")).encode("utf-8")

    def decrypt(cipher, key):
        return dec_fn(cipher.decode("utf-8"), key.decode("utf-8")).encode("utf-8")

    return encrypt, decrypt


def _transposition_adapter():
    """置换密码特殊：数据是 bytes、密钥是 str（列排序关键词）。"""
    def encrypt(payload, key):
        return TRANSPOSITION.encrypt(payload, key.decode("utf-8"))

    def decrypt(cipher, key):
        return TRANSPOSITION.decrypt(cipher, key.decode("utf-8"))

    return encrypt, decrypt


# ---------------------------------------------------------------------------
# 密钥规范化：让用户随意给一个字符串，也能得到符合各算法的密钥
# ---------------------------------------------------------------------------

def _bytes_key(n):
    """bytes 型密码：无 key 时随机生成；有 key 时用 SHA-256 派生出定长字节。"""
    def make(key_str=None):
        if key_str is None:
            return secrets.token_bytes(n)
        return hashlib.sha256(key_str.encode("utf-8")).digest()[:n]
    return make


def _str_key(default=b"LEMON"):
    """str 型密码：无 key 时用默认关键词；有 key 时直接编码成 UTF-8 字节。"""
    def make(key_str=None):
        return default if key_str is None else key_str.encode("utf-8")
    return make


# ---------------------------------------------------------------------------
# 注册表
# ---------------------------------------------------------------------------

def _entry(cipher_id, label, encrypt, decrypt, make_key):
    return {"id": cipher_id, "label": label,
            "encrypt": encrypt, "decrypt": decrypt, "make_key": make_key}


_ml_enc, _ml_dec = _str_adapter(MULTILITERAL.encrypt, MULTILITERAL.decrypt)
_pa_enc, _pa_dec = _str_adapter(POLYALPHA.encrypt, POLYALPHA.decrypt)
_pf_enc, _pf_dec = _str_adapter(PLAYFAIR.encrypt, PLAYFAIR.decrypt)
_tr_enc, _tr_dec = _transposition_adapter()

REGISTRY = {
    "multiliteral":   _entry("multiliteral",   "单表替代 Multiliteral", _ml_enc, _ml_dec, _str_key(b"KEYWORD")),
    "vigenere":       _entry("vigenere",       "多表替代 Vigenere",     _pa_enc, _pa_dec, _str_key(b"LEMON")),
    "playfair":       _entry("playfair",       "多图替代 Playfair",     _pf_enc, _pf_dec, _str_key(b"PLAYFAIR")),
    "transposition":  _entry("transposition",  "置换（列置换）",         _tr_enc, _tr_dec, _str_key(b"ZEBRAS")),
    "rc4":            _entry("rc4",            "流密码 RC4",            RC4.rc4_crypt, RC4.rc4_crypt, _bytes_key(16)),
    "ca":             _entry("ca",             "流密码 CA",             CA.ca_crypt,   CA.ca_crypt,   _bytes_key(16)),
    "des":            _entry("des",            "分块 DES",              DES.encrypt,   DES.decrypt,   _bytes_key(8)),
    "aes":            _entry("aes",            "分块 AES-128",          AES.encrypt,   AES.decrypt,   _bytes_key(16)),
}


def get(cipher_id):
    """按 id 取注册项，未知 id 抛出带可用列表的错误。"""
    if cipher_id not in REGISTRY:
        raise ValueError(f"未知密码: {cipher_id}，可选: {', '.join(REGISTRY)}")
    return REGISTRY[cipher_id]


def list_ciphers():
    """返回 [(id, label), ...]，供 CLI 展示。"""
    return [(cid, e["label"]) for cid, e in REGISTRY.items()]
