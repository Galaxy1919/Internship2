# 实训项目 TODO

范围：代码层面的遗留收尾 + 界面打磨。

## 待办

- [ ] 1. 桌面「验证中心」纳入新测试
      `desktop/main_window.py` 目前只跑 `verify.py` + `DH/test_integration.py`，
      需补上 `test_vectors.py`（官方向量）与 `DH/test_security.py`（安全信道），
      让"一键验证"覆盖 PROJECT_SHOWCASE.md 第 6 节的全部 4 条。

- [ ] 2. C 实现接入补齐（double_transposition + Autokey）
      目前只有 SM2 做了跨语言互操作（`publicKey/SM2/interop.py`），
      `double_transposition.c` 与 `PolyalphabeticSubstitution/main.c` 能编译但未接入
      （无 CLI / 无互操作 / 无基准）。要么补跨语言验证，要么在展示里明确
      "跨语言接入目前只 SM2"，避免答辩被追问露怯。

- [ ] 3. 清理死代码 agent_context.py
      `collect_context` / `compose_prompt` 是旧 agent（读 README/TODO 的问答）用的，
      新编排器已不再 import。删除或标注废弃。

- [ ] 4. 前端细节优化（web + desktop）
      清理界面里 AI 味重的 emoji 和装饰，统一细节（文案、间距、提示语、配色一致性），
      让界面更克制、专业。

## 答辩风险提示（非待办，答辩时心里有数）

- AES/DES 目前只有 ECB 模式（+PKCS7 填充），无 CBC/CTR。若老师问"用的什么分组模式、
  ECB 有什么问题"，备好说法：教学实现聚焦单块加解密，模式与 IV 是独立一层。
