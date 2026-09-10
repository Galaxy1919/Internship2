# 智能 Agent 设计文档（系统内密码学应用编排器）

> 状态：已实现并验证（三场景真机联调通过：混合加密 / 数字签名 / 加密保险箱）
> 范围：`desktop/` 内的智能助手，从"问答"升级为"能调用算法、编排出高层应用的 agent"。

## 1. 定位与边界

**一句话定位**：agent 是运行在密码学实验系统内部的功能模块。用户用自然语言描述需求，agent 把系统提供的**基础密码原语**（对称加密、公钥加密、签名、散列、完整性校验等）编排成**完整的高层应用流程**，并给出每一步的中间结果与最终产物。

**明确不做的事**（与验收/报告类"元工具"划清界限）：

- 不做项目验收、测试巡检、代码审查。
- 不替用户写实验报告、生成结论。
- 不对"项目本身"做元操作（这是"第四面墙"外的角色）。
- agent 是系统的**功能扩展**，不是系统的操作者。

## 2. 完整组件清单

一个 LLM agent 由以下 9 个部分组成，本表是每部分在本项目的落地：

| # | 组件 | 说明 | 本项目落地 |
|---|------|------|-----------|
| 1 | 模型 | 推理引擎 | DeepSeek（OpenAI 兼容），需支持 function calling，温度 ~0.2 |
| 2 | 系统提示 | 身份 + 目标 + 行为规则 | 字符串常量，见 §7 草稿 |
| 3 | 工具 + schema | 能做什么 + 调用格式契约 | `agent_cli.py` 的 10 个原语（§3）+ `agent_schemas.py` 的 JSON 定义 |
| 4 | 循环 | think→act→observe 迭代 | `agent_loop.py` 的 ReAct（§4），含终止条件 |
| 5 | 上下文管理 | 消息历史的累积/回填/截断 | `agent_loop.py` 内部（§5） |
| 6 | 权限/安全 | 能碰什么、不能碰什么 | 工具白名单 + 参数枚举校验（§6） |
| 7 | 错误处理 | 工具报错/超时/格式错怎么办 | 报错回喂模型自纠正 + 轮数上限（§4） |
| 8 | 记忆 | 短期/长期 | 短期 = 对话历史本身；长期 = 不需要 |
| 9 | 可观测性 | 记录并展示 agent 干了什么 | `agent_page.py` 步骤流 UI（§8） |

## 3. 工具层（10 个原语 CLI）

统一入口 `desktop/agent_cli.py`，argparse 子命令，每个子命令 = 一个工具。内部复用 `DH/cipher_registry.py`（与 `algorithm_runner.py` 相同的 sys.path 注入方式）。**输出统一 JSON**，便于模型无歧义地提取中间值传给下一步。

| 子命令 | 参数 | 返回 | 对应算法 |
|--------|------|------|---------|
| `sym_encrypt` | --cipher --text [--key] | 密文 hex + 实际使用的密钥 | aes/des/rc4/ca/vigenere/playfair/multiliteral/transposition |
| `sym_decrypt` | --cipher --ct --key | 明文 | 同上 |
| `make_key` | --cipher [--seed] | 密钥 | 对称密码 |
| `pubkey_keygen` | --cipher | 公钥 + 私钥（教学用，都返回） | rsa/elgamal/sm2 |
| `pubkey_encrypt` | --cipher --text --pubkey | 密文 hex | rsa/elgamal/sm2 |
| `pubkey_decrypt` | --cipher --ct --privkey | 明文 | rsa/elgamal/sm2 |
| `sign` | --cipher --message --privkey | 签名 | sm2（sm2-dsa）/elgamal（实现时确认 RSA 是否有签名） |
| `verify` | --cipher --message --sig --pubkey | 通过/失败 | 同上 |
| `hash` | --algo --text | 摘要 hex | md5 / sm3 |
| `hmac` | --text --key | MAC hex | HMAC-SHA256 |

调用示例：

```bash
python3 desktop/agent_cli.py sym_encrypt --cipher aes --text "hello" --key ""
# -> {"cipher":"aes","key":"<hex>","ciphertext":"<hex>"}

python3 desktop/agent_cli.py pubkey_keygen --cipher rsa
# -> {"cipher":"rsa","pubkey":"<...>","privkey":"<...>"}
```

**实现时需确认的点**：哪些公钥算法提供 sign/verify（SM2-DSA 确定有；ElGamal 有签名；RSA 需查证）、hash 的 sm3 是否已从 SM2 模块解出可直接调用。

## 4. 循环（ReAct）

```
输入：系统提示 + 消息历史 + tools 定义
循环（最多 12 轮）：
  1. 请求模型
  2. 若返回 content  -> 结束，返回最终回答
  3. 若返回 tool_calls -> 逐个执行：
       - 校验工具名在白名单内、参数合法
       - spawn `python3 desktop/agent_cli.py <subcommand> <args>`
       - 读 stdout 的 JSON，作为 role:"tool" 消息回填
       - 若工具报错（非零退出/异常）-> 把错误文本回喂，让模型自己纠正
  4. 回到 1
超轮数上限 -> 强停，返回"已达到最大步骤数"
```

终止条件：模型给出纯文本结论（无 tool_calls）；或达到 12 轮上限；或用户手动停止。

## 5. 上下文管理

消息结构：

```
[system]                系统提示（永久保留，不截断）
[user]                  用户自然语言需求
[assistant + tool_calls] 模型决定调用哪些工具
[tool]                  工具返回的 JSON（中间值：密钥/密文在此传递）
... （多轮重复）
[assistant]             最终结论
```

要点：

- **中间值靠上下文承载**：混合加密里 AES 密钥、密文、RSA 公钥都在 tool 消息里流转，模型负责把它们提取出来传给下一步。这是编排得以成立的关键。
- **截断策略**：token 超限时，保留 system + 最近若干轮，裁掉最早的中间轮；system 永不裁。
- 长期记忆不需要，每次任务从当前对话出发。

## 6. 权限与安全

- 工具是**固定白名单**：模型只能调 §3 的 10 个子命令，不能执行任意命令、不能碰文件系统、不能联网。
- **参数枚举校验**：cipher/algo 只能是枚举值，`agent_loop` 在 spawn 前先校验，杜绝注入。
- 模型输出的 JSON 参数会二次校验类型与取值范围，非法即回喂错误。

## 7. 系统提示（草稿）

> 你是运行在密码学实验系统内部的「密码学应用编排器」。用户会用自然语言描述一个加密/签名/校验需求，你调用系统提供的密码原语工具，把它们编排成完整的高层应用流程（例如混合加密、数字签名、加密保险箱）。
>
> 规则：
> 1. 只调用给定的工具，不要虚构工具或结果。
> 2. 动手前先在思考里规划好步骤，再逐条调用。
> 3. 工具返回的是真实算法输出，密钥和密文按原样传递，不要改动或编造。
> 4. 每一步之后根据真实结果决定下一步。
> 5. 用中文输出，最终给出清晰的产物与必要的中间结果说明。

## 8. 可观测性（UI 步骤流）

`agent_page.py` 的对话区不再只显示最终回答，而是把 agent 的每一步展开：

- 「规划」—— 模型调用工具前的思考（若模型支持 reasoning 字段则显示，否则靠 system prompt 让它先输出一句计划）。
- 「调用」—— 显示工具名 + 参数 + 返回的 JSON 摘要。
- 「结论」—— 最终产物。

场景按钮（保证答辩一键可靠，同时保留自由输入）：

- 混合加密（数字信封）
- 数字签名 + 篡改检测
- 加密保险箱

## 9. 三个旗舰应用（编排配方）

**A. 混合加密 / 数字信封**（推荐当旗舰）

编排（加密）：

```
make_key(aes)              -> AES 会话密钥 K
sym_encrypt(aes, 消息, K)  -> 密文 C1
pubkey_keygen(rsa)         -> (公钥 P, 私钥 S)
pubkey_encrypt(rsa, K, P)  -> 密文 C2（加密会话密钥）
产物：数字信封 { C2, C1 }
```

解密反向：pubkey_decrypt(rsa, C2, S) 还原 K -> sym_decrypt(aes, C1, K) 还原消息。

价值：项目目前做不到——RSA/SM2 有短消息长度限制，AES 无法分发密钥。混合加密正是 TLS/HTTPS/PGP 的核心套路。

**B. 数字签名 + 篡改检测**

```
hash(md5, 消息)          -> 摘要 H
sign(sm2, H, 私钥)       -> 签名 σ
verify(sm2, H, σ, 公钥)  -> 通过
（篡改消息后重算 H'）verify -> 失败，说明被篡改
```

**C. 加密保险箱（at-rest 存储）**

```
make_key(aes, seed=口令)   -> 由口令派生的密钥 K
sym_encrypt(aes, 秘密, K) -> 密文（存储）
... 取回时 sym_decrypt(aes, 密文, K) 还原
```

## 10. 文件结构

```
desktop/
  agent_cli.py      # 新增：10 个原语 CLI（argparse 子命令 + cipher_registry）
  agent_schemas.py  # 新增：喂给模型的 tools JSON 定义（name/description/parameters）
  agent_loop.py     # 新增：ReAct 循环 + 上下文管理 + 权限校验 + 错误处理
  agent_client.py   # 扩展：支持 tools 参数 + 解析 tool_calls + role:"tool" 消息
  agent_page.py     # 扩展：步骤流 UI + 场景按钮
```

## 11. 实施顺序

1. `agent_cli.py` —— 10 个原语，手动逐个验证正确（不接 agent）。
2. `agent_client.py` 扩展 —— function calling（tools + tool_calls + tool 角色消息）。
3. `agent_loop.py` —— ReAct 循环，先用假工具/真实 CLI 串通。
4. `agent_page.py` —— 步骤流 UI + 场景按钮。
5. 真实模型联调 —— 调 system prompt 与工具 description，直到旗舰场景（混合加密）每次都能正确编排。
