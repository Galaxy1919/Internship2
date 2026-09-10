from __future__ import annotations

"""喂给模型的工具定义（OpenAI function calling 格式）。

这些 schema 是模型"下单"和 agent_loop"接单"共同遵守的契约：
- name 对应 agent_cli.py 的子命令名
- parameters 里的字段名对应 CLI 的 --flag 名
- 描述必须把输入/输出格式写死（hex / 十进制 / 冒号分隔），模型才编得对
"""

SYM_CIPHERS = ["aes", "des", "rc4", "ca", "vigenere", "playfair", "multiliteral", "transposition"]
PUBKEY_CIPHERS = ["rsa", "elgamal", "sm2"]

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "make_key",
            "description": "生成对称密码的密钥。返回 JSON：{cipher, key}。key 是 hex 字符串（古典密码则为关键词字符串）。seed 缺省时随机生成。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": SYM_CIPHERS, "description": "对称密码名"},
                    "seed": {"type": "string", "description": "可选：由该种子派生密钥（如口令）。缺省随机。"},
                },
                "required": ["cipher"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sym_encrypt",
            "description": "对称加密文本。返回 JSON：{cipher, key, ciphertext}。key 缺省时自动生成并返回；ciphertext 是 hex。key 需先由 make_key 生成（hex 或关键词）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": SYM_CIPHERS},
                    "text": {"type": "string", "description": "明文"},
                    "key": {"type": "string", "description": "密钥（hex 或关键词）。缺省自动生成。"},
                },
                "required": ["cipher", "text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sym_decrypt",
            "description": "对称解密。返回 JSON：{plaintext}。ct 是 hex 密文，key 是与加密时一致的密钥。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": SYM_CIPHERS},
                    "ct": {"type": "string", "description": "hex 密文"},
                    "key": {"type": "string", "description": "密钥（hex 或关键词）"},
                },
                "required": ["cipher", "ct", "key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pubkey_keygen",
            "description": "生成公钥密钥对。返回 JSON：{cipher, pubkey, privkey}。RSA 公钥是 \"n:e\"、私钥是 \"n:d\"；SM2 公钥是 \"x:y\"、私钥是十进制 d；ElGamal 公钥是 \"p:g:y\"、私钥是 \"p:g:x:q\"。全是十进制数字。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": PUBKEY_CIPHERS, "description": "公钥密码名"},
                },
                "required": ["cipher"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pubkey_encrypt",
            "description": "公钥加密。返回 JSON：{cipher, ciphertext}，ciphertext 是 hex。注意：裸 RSA/ElGamal/SM2 只能加密短文本（长度受模数限制），长文本请用混合加密（先用对称密码加密正文，再用公钥加密会话密钥）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": PUBKEY_CIPHERS},
                    "text": {"type": "string", "description": "要加密的文本（短）"},
                    "pubkey": {"type": "string", "description": "公钥（来自 pubkey_keygen 返回的 pubkey）"},
                },
                "required": ["cipher", "text", "pubkey"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pubkey_decrypt",
            "description": "私钥解密。返回 JSON：{plaintext}。ct 是 hex 密文，privkey 是私钥（来自 pubkey_keygen 返回的 privkey）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": PUBKEY_CIPHERS},
                    "ct": {"type": "string", "description": "hex 密文"},
                    "privkey": {"type": "string", "description": "私钥"},
                },
                "required": ["cipher", "ct", "privkey"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sign",
            "description": "SM2 数字签名（SM2-DSA）。返回 JSON：{cipher, signature}，signature 是十进制 \"r:s\"。需要同时提供私钥和公钥（SM2 签名需公钥做 ZA 预处理）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": ["sm2"]},
                    "text": {"type": "string", "description": "要签名的消息"},
                    "privkey": {"type": "string", "description": "私钥（十进制 d）"},
                    "pubkey": {"type": "string", "description": "公钥 \"x:y\""},
                },
                "required": ["cipher", "text", "privkey", "pubkey"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify",
            "description": "SM2 验签。返回 JSON：{valid: true/false}。sig 是 \"r:s\"，pubkey 是 \"x:y\"，text 是原始消息（未被篡改的）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cipher": {"type": "string", "enum": ["sm2"]},
                    "text": {"type": "string", "description": "原始消息"},
                    "sig": {"type": "string", "description": "签名 \"r:s\""},
                    "pubkey": {"type": "string", "description": "公钥 \"x:y\""},
                },
                "required": ["cipher", "text", "sig", "pubkey"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hash",
            "description": "计算散列。返回 JSON：{algo, digest}，digest 是 hex（md5 为 32 位，sm3 为 64 位）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "algo": {"type": "string", "enum": ["md5", "sm3"]},
                    "text": {"type": "string", "description": "要散列的文本"},
                },
                "required": ["algo", "text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hmac",
            "description": "计算 HMAC-SHA256 消息认证码。返回 JSON：{mac}，mac 是 hex。用于完整性校验。",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "要校验的文本"},
                    "key": {"type": "string", "description": "HMAC 密钥"},
                },
                "required": ["text", "key"],
            },
        },
    },
]
