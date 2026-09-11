from __future__ import annotations

import json

from PyQt6.QtCore import QEvent, QSettings, QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QTextBrowser,
    QVBoxLayout, QWidget,
)

from .agent_client import AgentConfig, AgentError
from .agent_loop import run_agent

# 场景按钮：一键发送预设任务，保证答辩可靠；也保留自由输入
SCENES = [
    ("混合加密", "请用混合加密（数字信封）加密这条消息，并说明解密步骤："),
    ("数字签名", "请对这条消息做 SM2 数字签名，验签通过后，再演示消息被篡改后验签失败："),
    ("加密保险箱", "请用口令「123456」把这条秘密加密保存（模拟保险箱），再解密取回验证："),
]
DEFAULT_MESSAGE = "这是一条需要保护的秘密消息"
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"


def load_agent_config(settings: QSettings) -> AgentConfig:
    """启动时统一读取本机 Key，并固定使用 DeepSeek 官方地址和模型。"""
    # 地址和模型不再采用可能残留的旧值，避免 deepseek-flash 等旧配置导致请求失败。
    base_url = DEFAULT_BASE_URL
    model = DEFAULT_MODEL
    api_key = str(settings.value("api_key", "") or "").strip()
    auth_mode = str(settings.value("auth_mode", "bearer") or "bearer").strip()
    settings.setValue("base_url", base_url)
    settings.setValue("model", model)
    settings.setValue("auth_mode", auth_mode)
    settings.sync()
    return AgentConfig(base_url, api_key, model, auth_mode, "Authorization")


class SettingsDialog(QDialog):
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("助手设置")
        self.setMinimumWidth(560)
        form = QFormLayout(self)
        form.setContentsMargins(24, 24, 24, 16)
        form.setSpacing(12)
        self.base = QLineEdit(DEFAULT_BASE_URL)
        self.base.setReadOnly(True)
        self.base.setPlaceholderText("例如：https://api.deepseek.com")
        self.model = QLineEdit(DEFAULT_MODEL)
        self.model.setReadOnly(True)
        self.model.setPlaceholderText("例如：deepseek-v4-flash")
        self.key = QLineEdit(str(settings.value("api_key", "") or ""))
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setPlaceholderText("请输入 API Key")
        form.addRow("API 地址", self.base)
        form.addRow("模型", self.model)
        form.addRow("API Key", self.key)
        note = QLabel("模型需支持 OpenAI 兼容 function calling（DeepSeek 支持）。地址填 https://api.deepseek.com 即可。")
        note.setWordWrap(True)
        note.setObjectName("muted")
        form.addRow("说明", note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        self.settings = settings

    def accept(self):
        if not self.base.text().strip() or not self.model.text().strip():
            QMessageBox.warning(self, "配置不完整", "API 地址和模型不能为空。")
            return
        self.settings.setValue("base_url", self.base.text().strip())
        self.settings.setValue("model", self.model.text().strip())
        self.settings.setValue("api_key", self.key.text())
        self.settings.setValue("auth_mode", "bearer")
        self.settings.sync()
        super().accept()


class AgentWorker(QThread):
    step = pyqtSignal(dict)
    completed = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, config: AgentConfig, user_request: str):
        super().__init__()
        self.config = config
        self.user_request = user_request

    def run(self):
        try:
            answer, _ = run_agent(self.config, self.user_request, on_step=self.step.emit)
            self.completed.emit(answer)
        except AgentError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"助手请求失败：{exc}")


class AgentPage(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("CipherLabX", "DesktopLab")
        self.worker: AgentWorker | None = None
        self._work: QTextBrowser | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(3)
        title_col.addWidget(self._label("密码学应用编排器", "eyebrow"))
        title_col.addWidget(self._label("实验智能助手", "pageTitle"))
        header.addLayout(title_col)
        header.addStretch()
        self.connection = self._label("● 已配置，待测试", "muted")
        header.addWidget(self.connection)
        settings_btn = QPushButton("设置")
        settings_btn.clicked.connect(self.open_settings)
        header.addWidget(settings_btn)
        root.addLayout(header)

        # 场景按钮
        scenes = QHBoxLayout()
        scenes.setSpacing(8)
        for label, prefix in SCENES:
            b = QPushButton(label)
            b.clicked.connect(lambda _, p=prefix: self.send_scene(p))
            scenes.addWidget(b)
        scenes.addStretch()
        root.addLayout(scenes)

        self.chat_scroll = QScrollArea()
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.chat_body = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_body)
        self.chat_layout.setContentsMargins(8, 8, 8, 8)
        self.chat_layout.setSpacing(14)
        self.chat_layout.addStretch()
        self.chat_scroll.setWidget(self.chat_body)
        root.addWidget(self.chat_scroll, 1)

        composer = QHBoxLayout()
        composer.setSpacing(10)
        self.input = QPlainTextEdit()
        self.input.setPlaceholderText("描述你的加密/签名需求，Enter 发送，Shift+Enter 换行…")
        self.input.setFixedHeight(72)
        self.input.installEventFilter(self)
        composer.addWidget(self.input, 1)
        self.send_btn = QPushButton("发送")
        self.send_btn.setObjectName("primary")
        self.send_btn.setFixedWidth(88)
        self.send_btn.clicked.connect(self.send)
        composer.addWidget(self.send_btn)
        copy = QPushButton("复制回答")
        copy.setFixedWidth(88)
        copy.clicked.connect(self.copy_latest)
        composer.addWidget(copy)
        clear = QPushButton("清空")
        clear.setFixedWidth(72)
        clear.clicked.connect(self.clear_chat)
        composer.addWidget(clear)
        root.addLayout(composer)

        self.status = self._label("尚未发送消息", "muted")
        root.addWidget(self.status)
        self.add_assistant("你好。我可以把系统的密码原语编排成高层应用：混合加密（数字信封）、数字签名、加密保险箱。描述你的需求，或点上方场景按钮。")

    @staticmethod
    def _label(text: str, name: str) -> QLabel:
        x = QLabel(text)
        x.setObjectName(name)
        x.setWordWrap(True)
        return x

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.connection.setText("● 已配置，待测试")

    # ---------- 气泡 ----------
    def add_user(self, text: str):
        bubble = QLabel(text)
        bubble.setObjectName("userBubble")
        bubble.setWordWrap(True)
        bubble.setMaximumWidth(720)
        bubble.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row = QHBoxLayout()
        row.setContentsMargins(70, 0, 0, 0)
        row.addStretch()
        row.addWidget(bubble)
        self.chat_layout.insertLayout(self.chat_layout.count() - 1, row)

    def add_assistant(self, markdown: str):
        bubble = QTextBrowser()
        bubble.setObjectName("assistantBubble")
        bubble.setMarkdown(markdown)
        bubble.setOpenExternalLinks(False)
        bubble.setReadOnly(True)
        bubble.setMinimumHeight(70)
        bubble.setMaximumHeight(520)
        bubble.setMaximumWidth(820)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 70, 0)
        row.addWidget(bubble)
        row.addStretch()
        self.chat_layout.insertLayout(self.chat_layout.count() - 1, row)

    def _remove_last_assistant(self):
        if self.chat_layout.count() < 2:
            return
        item = self.chat_layout.takeAt(self.chat_layout.count() - 2)
        layout = item.layout()
        if layout is None:
            return
        while layout.count():
            child = layout.takeAt(0)
            widget = child.widget()
            if widget:
                widget.deleteLater()
        layout.deleteLater()

    # ---------- 工作区（实时显示编排步骤） ----------
    def _begin_work(self):
        work = QTextBrowser()
        work.setObjectName("workBubble")
        work.setMarkdown("**正在编排…**\n")
        work.setOpenExternalLinks(False)
        work.setReadOnly(True)
        work.setMinimumHeight(60)
        work.setMaximumHeight(520)
        work.setMaximumWidth(820)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 70, 0)
        row.addWidget(work)
        row.addStretch()
        self.chat_layout.insertLayout(self.chat_layout.count() - 1, row)
        self._work = work

    def _append_work(self, md: str):
        if self._work is None:
            return
        self._work.setMarkdown(self._work.toMarkdown() + md)
        self.chat_scroll.verticalScrollBar().setValue(self.chat_scroll.verticalScrollBar().maximum())

    def _finish_work(self, final_md: str):
        # 移除工作区，追加最终回答
        self._remove_last_assistant()
        self._work = None
        self.add_assistant(final_md)
        self.chat_scroll.verticalScrollBar().setValue(self.chat_scroll.verticalScrollBar().maximum())

    # ---------- 发送 ----------
    def send(self):
        text = self.input.toPlainText().strip()
        if text:
            self.send_text(text)

    def send_scene(self, prefix: str):
        msg = self.input.toPlainText().strip() or DEFAULT_MESSAGE
        self.send_text(prefix + " " + msg)

    def eventFilter(self, watched, event):
        if watched is self.input and event.type() == QEvent.Type.KeyPress and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if not (event.modifiers() & Qt.KeyboardModifier.ShiftModifier):
                self.send()
                return True
        return super().eventFilter(watched, event)

    def copy_latest(self):
        browsers = self.chat_body.findChildren(QTextBrowser)
        if not browsers:
            self.status.setText("暂无可复制的回答")
            return
        QApplication.clipboard().setText(browsers[-1].toPlainText())
        self.status.setText("最新回答已复制")

    def send_text(self, text: str):
        if self.worker and self.worker.isRunning():
            return
        self.input.clear()
        self.add_user(text)
        self._begin_work()
        self.send_btn.setEnabled(False)
        self.connection.setText("● 编排中...")
        self.status.setText("正在调用密码原语并编排...")
        config = load_agent_config(self.settings)
        self.worker = AgentWorker(config, text)
        self.worker.step.connect(self.on_step)
        self.worker.completed.connect(self.on_answer)
        self.worker.failed.connect(self.on_error)
        self.worker.start()

    def on_step(self, step: dict):
        if step["type"] == "thought":
            self._append_work(f"\nTHINK {step['content']}\n")
        else:
            name = step["name"]
            args_s = json.dumps(step["args"], ensure_ascii=False)
            res = step["result"]
            res_s = res if len(res) <= 90 else res[:90] + "..."
            status = "PASS" if step["ok"] else "FAIL"
            self._append_work(f"\n{status} `{name}` {args_s}\n\n  -> `{res_s}`\n")

    def on_answer(self, text: str):
        self._finish_work(text)
        self.send_btn.setEnabled(True)
        self.connection.setText("● 已连接")
        self.status.setText("编排完成")

    def on_error(self, text: str):
        self._finish_work("**请求失败**\n\n" + text)
        self.send_btn.setEnabled(True)
        self.connection.setText("● 请求失败")
        self.status.setText("请检查设置后重试")

    def clear_chat(self):
        self._work = None
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.layout():
                while item.layout().count():
                    child = item.layout().takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()
                item.layout().deleteLater()
        self.add_assistant("会话已清空。你可以重新提问。")
        self.connection.setText("● 未连接")
        self.status.setText("尚未发送消息")
