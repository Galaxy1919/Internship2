# 实训项目 TODO

范围：代码层面的遗留收尾 + 界面打磨。

## 待办

- [x] 1. 桌面「验证中心」纳入新测试
      `desktop/main_window.py` 已通过根目录 `run_tests.py` 统一纳入 `verify.py`、
      `test_vectors.py`、`DH/test_integration.py`、`DH/test_security.py` 与 `c_verify.py`，
      让"一键验证"覆盖官方向量、交叉验证、双机集成、安全信道和 C 实现验证。

- [x] 2. C 实现接入补齐（SM2 + Autokey + double_transposition）
      已新增 `c_verify.py`：统一编译 SM2 / Autokey / 双重置换 C 实现，运行 SM2
      点乘自检、Python↔C 互操作、SM2 单进程 bench/batch、Autokey 桥接自检、双重置换 selftest
      与桥接自检。说明口径：SM2 是同算法跨语言互操作；Autokey C 对应
      Autokey-plaintext；双重置换 C 是扩展算法，不宣称与 Python 列置换互操作。

- [x] 3. 清理死代码 agent_context.py
      `collect_context` / `compose_prompt` 没有被现有代码引用，已删除旧模块。

- [x] 4. 前端细节优化（web + desktop）
      清理界面里 AI 味重的 emoji 和装饰，统一细节（文案、间距、提示语、配色一致性），
      让界面更克制、专业。

## 答辩风险提示（非待办，答辩时心里有数）

- AES/DES 目前只有 ECB 模式（+PKCS7 填充），无 CBC/CTR。若老师问"用的什么分组模式、
  ECB 有什么问题"，备好说法：教学实现聚焦单块加解密，模式与 IV 是独立一层。
