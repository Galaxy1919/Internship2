# Internship2 — 信息安全工程实训2

面向 AI 辅助开发的代码库说明。本文档写给将要在此仓库上工作的 agent（Codex / Claude Code / Hermes 等），
目的是让 agent 快速理解架构、模块职责、统一接口和必须遵守的约定，避免踩坑。不是面向课程展示的项目介绍。

## 1. 项目定位

- 东北大学软件学院《信息安全工程实训2》课程项目。
- 实现一个加解密系统，分两大块（对应任务书要求）：
  - 单机加解密实践：9 类密码算法的从零实现。
  - 双机加解密实践：Socket 通信，一端加密、另一端解密，含文件传输与 DH 密钥交换。
- 技术栈：
  - Python（密码算法 + 双机框架），仅用标准库，不依赖第三方密码库。
  - TypeScript / Next.js（单机统一展示界面 `web/`，浏览器端独立实现）。
- 协作约定：合作者，直接 commit + push 到 `main`，不走 PR。当前 TODO 见 `TODO.md`。

## 2. 目录结构与模块职责

```
Internship2/
├── ClassicalCiphers/                古典密码（每类一个 main.py）
│   ├── MonoalphabeticSubstitution/MultiliteralCipher/   单表替代（Polybius 方阵）
│   ├── PolyalphabeticSubstitution/                      多表替代（Vigenere + Autokey 明文/密文）
│   └── Transposition/                                   置换（列置换）
├── Playfair cipher/                 多图替代 Playfair（5×5 方阵 + 双字母组）
├── stream/                          流密码
│   ├── RC4/                         RC4（KSA + PRGA）
│   └── CA/                          元胞自动机流密码（Rule 30 等）
├── Block/                           分块密码
│   ├── DES/                         DES（手写 S-box + Feistel）
│   └── AES/                         AES-128（手写 S-box + 轮函数）
├── publicKey/                       公钥密码
│   ├── RSA/                         RSA（Miller-Rabin + CRT + 低指数攻击演示）
│   ├── ECC/                         椭圆曲线（secp256k1，仅 ECDH，无消息加密）
│   ├── Elgamal/                     ElGamal（安全素数 + k 重用攻击演示）
│   └── SM2/                         国密 SM2（手写 SM3 + SM2-PKE + 签名）
├── MD5/                             单向散列 MD5（RFC 1321）
├── DH/                              双机加解密框架（重点）
│   ├── main.py                      单机 DH 演示（不涉及 socket）
│   ├── dh_socket_common.py          通信层：帧协议 + DH + 传输密码加密/HMAC + 文件分块
│   ├── cipher_registry.py           适配层：统一加载所有密码 + 归一接口 + 分派
│   ├── encrypt_client.py            加密端 CLI
│   ├── decrypt_server.py            解密端 CLI
│   └── test_integration.py          端到端验收（消息/文件/对称/公钥/摘要/ECDH）
├── web/                             Next.js 单机统一界面（队友负责，TypeScript）
├── verify.py                        交叉验证脚本（MD5/RC4/CA 对比标准库）
├── main.py                          根目录 PyCharm 模板，未使用，忽略
├── view/main.py                     空文件，未使用，忽略
└── start.bat                        Windows 启动 web 的脚本
```

## 3. 架构分层（双机框架）

双机加解密分三层。注意：这里的「层」指代码内部职责分工，不是网络协议栈的五层/七层模型。

1. 通信层（`DH/dh_socket_common.py`）
   - 帧协议：JSON 帧（`send_frame`/`recv_frame`）与二进制帧（`send_bytes`/`recv_bytes`），长度前缀 `!I`。
   - DH 密钥交换（小素数 7919/5，固定私钥 1234/5678，教学用），用 KDF 派生「传输密码所需长度的密钥」+ HMAC 密钥。
   - 传输密码可动态指定（默认 `aes`，可选 `des`/`rc4`/`ca`）：整个信封用「DH 派生的密钥 + 所选传输密码 + HMAC」
     加密后再传，网络上传的永远是密文。因为密钥由 DH 协商，任意所选传输密码都满足「至少一个密码用 DH 交换密钥」。
   - 文件传输：64KB 分块，每块传输密码加密 + HMAC（sha256 标签 64 字节 hex 拼在密文尾部），末尾空帧做 EOF。

2. 适配层（`DH/cipher_registry.py`）
   - 用 importlib 动态加载所有密码模块（详见第 7 节陷阱）。
   - 把五花八门的底层接口归一成统一接口（第 4 节）。
   - 提供 cipher_id → 函数的注册表，解密端按 id 动态分派。

3. 加密端 / 解密端（`DH/encrypt_client.py` / `DH/decrypt_server.py`）
   - 加密端选算法 → 加密 → 装信封 → 交通信层加密 → 发送。
   - 解密端解密通信层 → 按 cipher_id 分派 → 解密。

## 4. 统一接口（cipher_registry.py）

### 4.1 对称密码（`REGISTRY`）

cipher_id：`multiliteral` `vigenere` `playfair` `transposition` `rc4` `ca` `des` `aes`

每个注册项提供：
```python
{
  "id": str,
  "label": str,                        # 中文名，用于打印
  "encrypt": fn(payload: bytes, key: bytes) -> bytes,
  "decrypt": fn(cipher: bytes, key: bytes) -> bytes,
  "make_key": fn(key_str=None) -> bytes,   # 无 key 时生成默认/随机密钥；有 key 时规范化
}
```
- bytes 型密码（AES/DES/RC4/CA）：`make_key` 无参时 `secrets.token_bytes(n)`，有 key 字符串时 SHA-256 派生定长。
- str 型密码（古典四种）：`make_key` 无参时返回默认关键词，有 key 字符串时 UTF-8 编码；适配器内部做 str↔bytes 转换。

### 4.2 公钥密码（`PUBKEY_REGISTRY`，反向密钥流）

cipher_id：`rsa` `elgamal` `sm2`

```python
{
  "id": str,
  "label": str,
  "generate": fn() -> (private, public_str),     # 解密端调用，public_str 为 "x:y:..." 序列化
  "encrypt": fn(payload: bytes, public_str) -> bytes,
  "decrypt": fn(ciphertext: bytes, private) -> bytes,
}
```
- 公钥密码密钥流是反的：解密端先生成密钥对、把公钥发给加密端，加密端用公钥加密，解密端用私钥解。

### 4.3 MD5 与 ECC

```python
md5_hex(payload: bytes) -> str                 # MD5 十六进制摘要，双机做完整性校验
ecc_generate_keypair() -> (d, Q)               # ECC(secp256k1) 密钥对
ecc_ecdh(priv, peer_pub) -> Point              # ECDH 共享点
ecc_point_serialize(p) -> str                  # 点序列化 "x:y"（hex）
ecc_point_parse(s) -> tuple                    # 还原点
```

## 5. 双机通信协议（帧类型）

帧为长度前缀 JSON；`session` 为 DH 交换记录的指纹（transcript_hash 前 16 hex），每帧校验。

| 帧类型 | 方向 | 说明 |
|---|---|---|
| `dh_hello` / `dh_reply` | C→S / S→C | DH 握手，交换公开值；`dh_hello` 附带 `transport` 协商传输密码 |
| `encrypted_message` | C→S | 消息，经通信层用传输密码加密 |
| `file_meta` | C→S | 文件元信息，后跟二进制分块 + EOF 空帧 |
| `cipher_message` | C→S | 对称密码：信封 `{cipher, key, payload}`（均 hex），整信封经通信层加密 |
| `pubkey_request` / `pubkey_reply` | C→S / S→C | 公钥反向流：请求公钥 / 返回公钥 |
| `pubkey_message` | C→S | 公钥密文（hex），经通信层加密 |
| `digest_verify` | C→S | 信封 `{message, digest}`，解密端重算摘要比对 |
| `ecdh_hello` / `ecdh_reply` | C→S / S→C | ECDH 交换公钥点，双方各自算出共享点 |

`decrypt_server.py` 的 `serve()` 用「会话内多帧循环」处理：`pubkey_request`、`ecdh_hello` 是中间帧
（`continue`），其余是终结帧（处理后 `break`）。

## 6. 加密端 CLI（encrypt_client.py）

```
python3 encrypt_client.py [message]                # 默认 AES 传输密码加密消息
python3 encrypt_client.py --file PATH [--plain]    # 发文件（默认 AES 加密，--plain 明文）
python3 encrypt_client.py --cipher aes --text ... [--key ...]   # 8 个对称密码任选
python3 encrypt_client.py --pubkey rsa --text ...  # 公钥密码（rsa/elgamal/sm2）
python3 encrypt_client.py --digest --text ...      # MD5 完整性校验
python3 encrypt_client.py --ecdh                   # ECC-ECDH 密钥交换
# 通用：--host --port --transport（默认 127.0.0.1:29090；传输密码 aes/des/rc4/ca，默认 aes）
```

解密端：`python3 decrypt_server.py [--host --port]`（每次连接处理完一个会话后退出，once=True）。

## 7. 关键陷阱与约定（agent 必读）

1. **所有密码模块都叫 `main.py`**，不能直接 `import main`（会重名冲突）。必须走
   `cipher_registry._load(name, path)` 动态加载；`_load` 里 `sys.modules[name] = mod` 这一行不能省——
   SM2/ECC 用了 `@dataclass`，不注册进 sys.modules 会导致 dataclass 解析注解时崩溃。

2. **古典密码只处理 A-Z**。它们用 `ch.isalpha()` 过滤，而 Python 对中文也返回 True，中文密钥/明文会把方阵
   撑坏（如 Multiliteral 报「方阵字母数异常」）。给古典密码传关键词时只传 A-Z。

3. **RSA/ElGamal 是裸实现（无填充）**，明文必须小于模数 n（RSA）或 p（ElGamal），只适合短消息。
   双机演示里 RSA 用 512-bit、ElGamal 用 128-bit（安全素数生成慢），见 `RSA_BITS`/`ELGAMAL_BITS`。

4. **ECC 只有 ECDH，没有消息加密**。双机里它的角色是 `--ecdh` 密钥交换，不是消息加解密。

5. **web/ 是独立 TypeScript 实现**，与 Python 密码模块完全无关（每类算法在 `web/src/lib/*.ts` 重写）。
   单机统一界面由队友负责，Python 侧 agent 不要动 web/。

6. **双机 = localhost 模拟**。两个进程走 127.0.0.1 就是「两台机器」；换真机只改 `--host` 成对方 IP，代码不变。

7. **新增一个密码的步骤**（保持现有结构）：
   a. 在对应目录写自包含的 `main.py`（仅标准库，含 encrypt/decrypt 函数 + `--selftest` + `if __name__ == "__main__"` 守卫）。
   b. 在 `cipher_registry.py` 顶部 `_load` 该模块。
   c. 写适配器，把它的原生接口包成 `bytes -> bytes`（对称）或 `generate/encrypt/decrypt`（公钥）。
   d. 注册进 `REGISTRY` 或 `PUBKEY_REGISTRY`，对称密码配好 `make_key`。
   e. 在 `test_integration.py` 对应测试里补一条。

## 8. 运行与测试

```bash
# 单个密码自检（每个 main.py 都有）
python3 MD5/main.py --selftest
python3 Block/AES/main.py          # 或 --selftest / 交互模式
python3 publicKey/RSA/main.py --selftest

# 交叉验证（MD5/RC4/CA 对比标准库）
python3 verify.py

# 双机端到端验收（覆盖所有帧类型，全部 PASS 才通过）
cd DH && python3 test_integration.py

# web 前端（队友负责）
cd web && npm install && npm run dev   # http://localhost:3900
```

## 9. 当前进度与分工

- 单机密码算法：9 类全部实现（含公钥四件套）。
- 双机加解密：文件传输 + 全部密码移植 + 公钥反向流 + MD5 + ECDH 已跑通。
- 待办见 `TODO.md`：单机统一界面补齐（队友）、双机界面（图2/图3）、扩展内容（未定）。
- 报告与 PPT 不在仓库内，不属于本 README 范畴。
