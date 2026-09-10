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
│        ├── sm2.c / sm3.c / bn.c     同算法的 C 独立实现（256-bit 大整数库）
│        ├── sm2_cli.c                C 版命令行接口（keygen/enc/dec）
│        └── interop.py               Python↔C 跨语言互操作 + 基准
├── MD5/                             单向散列 MD5（RFC 1321）
├── DH/                              双机加解密框架（重点）
│   ├── main.py                      单机 DH 演示（不涉及 socket）
│   ├── dh_socket_common.py          通信层：帧协议 + DH + 传输密码加密/HMAC + 文件分块
│   ├── cipher_registry.py           适配层：统一加载所有密码 + 归一接口 + 分派
│   ├── encrypt_client.py            加密端 CLI
│   ├── decrypt_server.py            解密端 CLI
│   ├── mitm.py                      中间人攻击演示（认证 DH 攻防对照）
│   ├── test_integration.py          端到端验收（消息/文件/对称/公钥/摘要/ECDH）
│   └── test_security.py             安全信道测试（认证 DH + MITM + 重放保护）
├── web/                             Next.js 单机统一界面（队友负责，TypeScript）
├── verify.py                        交叉验证脚本（MD5/RC4/CA 对比标准库）
├── test_vectors.py                  标准测试向量（NIST AES/DES + GM/T SM3）
├── main.py                          根目录 PyCharm 模板，未使用，忽略
├── view/main.py                     空文件，未使用，忽略
└── start.bat                        Windows 启动 web 的脚本
```

## 3. 架构分层（双机框架）

双机加解密分三层。注意：这里的「层」指代码内部职责分工，不是网络协议栈的五层/七层模型。

1. 通信层（`DH/dh_socket_common.py`）
   - 帧协议：JSON 帧（`send_frame`/`recv_frame`）与二进制帧（`send_bytes`/`recv_bytes`），长度前缀 `!I`。
   - DH 密钥交换（小素数 7919/5，固定私钥 1234/5678，教学用），用 KDF 派生「传输密码所需长度的密钥」+ HMAC 密钥。
   - 认证 DH（防中间人）：Bob 用长期 SM2 身份密钥对 DH 交换 transcript 做签名，Alice 持 Bob 公钥验签；验签失败即说明公开值被中间人替换。原始 DH 无法防 MITM，攻防对照见 `mitm.py`。
   - 重放保护：握手后每个 JSON 帧带递增 `seq` 序号，解密端校验严格递增，重复/乱序帧被拒。
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
# 认证 DH：--bob-pubkey（Bob 身份公钥，默认内置）/ --no-auth（关闭验签，教学观察 MITM）
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

# 标准测试向量（NIST AES/DES + GM/T SM3，证明与标准一致）
python3 test_vectors.py

# 双机端到端验收（覆盖所有帧类型，全部 PASS 才通过）
cd DH && python3 test_integration.py

# 安全信道测试（认证 DH / MITM 攻防 / 重放保护）
cd DH && python3 test_security.py

# C 跨语言互操作 + 基准（先编译 C 版 SM2）
cd publicKey/SM2 && cc -O2 -o sm2_cli sm2_cli.c sm2.c sm3.c bn.c && python3 interop.py --selftest

# web 前端（队友负责）
cd web && npm install && npm run dev   # http://localhost:3900
```

## 9. 当前进度与分工

- 单机密码算法：9 类全部实现（含公钥四件套）。
- 双机加解密：文件传输 + 全部密码移植 + 公钥反向流 + MD5 + ECDH 已跑通。
- 待办见 `TODO.md`：单机统一界面补齐（队友）、双机界面（图2/图3）、扩展内容（未定）。
- 报告与 PPT 不在仓库内，不属于本 README 范畴。

## 10. 桌面端使用（PyQt6）

`desktop/` 是在保留原有算法、双机协议和 `web/` 的基础上新增的桌面展示端。桌面端不替换队友实现，主要通过 `cipher_registry.py`、现有 CLI 和原有测试脚本完成调用。

### 10.1 安装与启动

macOS / Linux：

```bash
cd /Users/lmt/Desktop/Internship2
python3 -m pip install -r desktop/requirements.txt
python3 desktop/run_desktop.py
```

Windows：

```bash
cd Internship2
py -m pip install -r desktop/requirements.txt
py desktop/run_desktop.py
```

如果系统提示找不到 `PyQt6`，先执行依赖安装命令；不要修改算法目录的导入路径。桌面端启动后窗口标题为 `CipherLab X · 密码工程实验控制台`。

### 10.2 桌面端功能

- `总览`：查看算法、双机信道、攻击实验和验证中心入口。
- `算法实验`：选择现有算法，输入明文和密钥，调用原有实现并显示密文、解密结果和往返验证。
- `双机信道`：启动现有 `DH/decrypt_server.py` 与 `DH/encrypt_client.py`，执行消息或文件传输，显示 Alice、Bob、DH、传输密码、HMAC 和解密状态。
- `攻击实验`：调用 `publicKey/Elgamal/main.py --demo`，观察随机数 `k` 复用导致 `r` 相同并恢复私钥的教学实验。
- `验证中心`：在后台线程执行 `verify.py` 和 `DH/test_integration.py`，避免测试过程冻结界面。
- `智能助手`：系统内密码学应用编排器（agent）。在设置中填写 API 地址、模型和 API Key 后，助手调用 10 个密码原语（对称/公钥/SM2 签名验签/散列/HMAC），把它们编排成高层应用流程（混合加密、数字签名、加密保险箱），并在对话区实时展示编排步骤。工具层封装为 `agent_cli.py`（CLI + 统一 JSON 输出），循环用 ReAct。

### 10.3 智能助手配置

点击 `智能助手` 页面右上角的 `设置`，填写：

```text
API 地址：https://api.deepseek.com
模型：deepseek-v4-flash
API Key：你的 API Key
```

程序会自动请求：

```text
POST https://api.deepseek.com/chat/completions
Authorization: Bearer 你的 API Key
```

API Key 使用密码框显示，并保存到本机 `QSettings`，不会写入本仓库。输入 Key 时可以填写原始 Key，也可以填写带 `Bearer ` 前缀的 Key，程序会自动去重。其他 OpenAI 兼容服务可以填写其 Base URL，程序会自动补齐 `/v1/chat/completions`。

助手页面支持：

- 多轮对话；
- Enter 发送、Shift+Enter 换行；
- 助手回答中的标题、列表、加粗、代码块和基础表格 Markdown 渲染；
- 复制最新回答；
- 清空当前会话；
- 三个场景按钮：`混合加密`、`数字签名`、`加密保险箱`；
- 实时展示编排过程（思考 + 每个工具调用 + 返回结果）。

### 10.4 双机消息演示

1. 打开 `双机信道`。
2. 选择传输密码，默认使用 AES。
3. 输入消息。
4. 点击 `运行真实双机链路`。
5. 观察 Bob 进入就绪状态，Alice 发起连接。
6. 检查两端的 DH 共享秘密是否一致。
7. 检查传输密码、密文、HMAC 和解密结果。
8. 看到 `双机通信完成` 后，再点击 `验证中心`运行全量测试。

桌面端的双机演示默认使用本机两个进程和 `127.0.0.1`，属于本机模拟双机。更换为真实两台设备时，应按现有 CLI 的 `--host`、`--port` 参数部署，不要把教学用固定 DH 参数描述成生产安全配置。

### 10.5 文件传输演示

1. 在 `双机信道` 点击 `选择文件并发送`。
2. 选择文件后确认状态栏显示已选择文件。
3. 点击 `运行真实双机链路`。
4. 桌面端调用现有 `encrypt_client.py --file`。
5. Bob 使用现有分块接收逻辑保存文件。
6. 在 Bob 日志中查看文件名、文件大小和保存路径。

现有后端使用 64KB 分块、传输密码和 HMAC 校验；桌面端只负责操作入口和状态展示。

## 11. 答辩讲解建议

答辩时不要按 14 个算法逐个念。建议按“功能—实现—验证—安全问题”讲解，现场只展示最有代表性的三个模块。

### 11.1 开场介绍

可以这样说：

> 本项目实现了一个信息加解密实验系统，包含多种手写密码算法、基于 Socket 的双机通信，以及用于观察算法安全问题的攻击实验。桌面端是在保留原有算法和通信代码的基础上增加的统一操作界面。

### 11.2 展示单机算法

推荐先演示 AES、RSA 或 DH 中的一个：

> 这里输入明文和密钥后，桌面端调用仓库原有算法完成加密和解密。页面同时显示密文、解密结果和往返验证，说明这不是预先写好的演示文本，而是实际运行得到的结果。

如果老师追问“是不是调用密码库”：

> 核心算法位于仓库对应目录，AES、RSA、DH 等关键计算由项目代码完成。桌面端只负责参数输入、进程调用和结果展示，没有用第三方密码库替换算法实现。

### 11.3 展示双机通信

推荐按照下面顺序操作：

1. 选择 AES 作为传输密码；
2. 输入一条短消息；
3. 启动双机链路；
4. 查看 Alice 和 Bob 两栏日志；
5. 指出 DH 共享秘密一致；
6. 指出密文经过传输密码保护；
7. 指出 HMAC 校验通过；
8. 指出 Bob 最终还原明文并返回 ACK。

可以这样讲：

> 双机部分不是简单地把明文从一个窗口复制到另一个窗口。通信先进行 DH 密钥交换，再用共享秘密派生传输密钥和 HMAC 密钥，之后才发送加密数据。解密端先校验完整性，再进行解密，最后返回 ACK。

### 11.4 展示攻击实验

推荐演示 ElGamal 随机数复用：

> 这里演示的是密码算法的错误使用。ElGamal 签名如果两次复用同一个随机数 k，会造成两次签名的 r 相同。攻击者利用两条签名可以恢复 k，进一步恢复私钥。项目中的演示会直接输出恢复结果，并与真实私钥进行比较。

如果老师问“项目如何修复”：

> 修复方式是每次签名都使用新的、不可预测的随机数 k，不能因为调试方便而复用随机数。这个实验说明密码算法本身正确，不代表使用方式一定安全。

### 11.5 展示验证中心

最后运行验证中心，说明：

> 验证中心直接执行项目已有的 `verify.py` 和 `DH/test_integration.py`。前者验证 MD5、RC4、CA 等算法，后者覆盖消息、文件、对称密码、公钥密码、摘要校验、ECDH 和动态传输密码。这里显示的是本次真实运行结果。

### 11.6 智能助手如何讲

如果展示智能助手，可以这样说：

> 智能助手不是密码算法的替代实现，而是系统内的密码学应用编排器。它调用项目自己的密码原语（封装成 CLI），把基础算法编排成混合加密、数字签名、加密保险箱等高层应用。模型只负责规划步骤和调度工具，真正的加密计算仍由项目代码执行；口令派生密钥用加盐的 PBKDF2，而不是简单散列。

### 11.7 结束总结

可以这样收尾：

> 本项目的重点不只是实现了多少种算法，而是把单机实验、双机通信、完整性校验和安全攻击放在同一个可运行系统中。桌面端保留了团队原有代码，并将这些功能组织成了更适合实验操作和现场展示的界面。

## 12. 常见答辩问题

| 问题 | 建议回答 |
|---|---|
| 为什么使用 DH？ | DH 用于让通信双方在公开信道上协商共享秘密，项目再用共享秘密派生传输密钥。 |
| DH 能不能防中间人攻击？ | 原始 DH 不认证身份，不能单独抵抗中间人攻击；项目保留了篡改演示，实际系统还需要数字签名或证书。 |
| 为什么还实现 MD5？ | MD5 已不适合安全密码用途，但它适合作为单向散列函数的历史教学和雪崩效应实验。 |
| RSA 能不能加密任意大文件？ | 当前是教学用裸 RSA，只适合短消息；实际文件应使用混合加密，由 RSA/SM2 保护会话密钥。 |
| 为什么桌面端不重写算法？ | 为了保留团队原有实现和测试结果，桌面端负责统一调用和展示，降低对已完成代码的影响。 |
| 桌面端和网页端是什么关系？ | `web/` 是原有独立网页端，`desktop/` 是新增的本地桌面操作端，两者共用项目算法思想，但不互相替换。 |

