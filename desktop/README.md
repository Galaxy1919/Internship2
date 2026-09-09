# CipherLab X 桌面端

本目录是 Internship2 的独立 PyQt6 桌面展示端，不替换 `web/`，不重写算法核心和 DH 协议。

启动：

```bash
python3 -m pip install -r desktop/requirements.txt
python3 desktop/run_desktop.py
```

模块：

- 总览：项目主线与四个演示入口
- 单机算法：统一实验入口，重点展示 AES/RSA/DH 的过程说明
- 双机信道：调用仓库原有 `DH/decrypt_server.py` 与 `DH/encrypt_client.py`
- 攻击实验：调用 ElGamal 原有 `--demo`，展示随机数复用风险
- 验证中心：实际执行 `verify.py` 与 `DH/test_integration.py`

说明：桌面端新增代码优先保持只读复用旧模块；算法目录、`web/` 和双机协议不在本次桌面端中重写。
