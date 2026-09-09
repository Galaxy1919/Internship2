from __future__ import annotations

import subprocess
from pathlib import Path

from PyQt6.QtCore import QEvent, QSettings, QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QTextBrowser,
    QVBoxLayout, QWidget,
)

from .agent_client import AgentConfig, AgentError, chat
from .agent_context import collect_context, compose_prompt


class SettingsDialog(QDialog):
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("助手设置")
        self.setMinimumWidth(560)
        form = QFormLayout(self)
        form.setContentsMargins(24, 24, 24, 16)
        form.setSpacing(12)
        self.base = QLineEdit(settings.value("base_url", "https://api.deepseek.com"))
        self.base.setPlaceholderText("例如：https://api.deepseek.com")
        self.model = QLineEdit(settings.value("model", "deepseek-v4-flash"))
        self.model.setPlaceholderText("例如：deepseek-v4-flash")
        self.key = QLineEdit(settings.value("api_key", ""))
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setPlaceholderText("请输入 API Key")
        form.addRow("API 地址", self.base)
        form.addRow("模型", self.model)
        form.addRow("API Key", self.key)
        note = QLabel("DeepSeek 官方地址直接填写 https://api.deepseek.com；程序会自动请求 /chat/completions。")
        note.setWordWrap(True); note.setObjectName("muted"); form.addRow("说明", note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); form.addRow(buttons)
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
    completed = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, config: AgentConfig, messages: list[dict[str, str]]):
        super().__init__(); self.config = config; self.messages = messages

    def run(self):
        try:
            system = "你是密码学实验助手。只根据给出的项目上下文回答；不虚构运行结果，不执行命令，不泄露 API 密钥。使用清晰的中文 Markdown，必要时使用标题、列表和代码块。"
            self.completed.emit(chat(self.config, system, self.messages))
        except AgentError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"助手请求失败：{exc}")


class AgentPage(QWidget):
    def __init__(self):
        super().__init__(); self.settings = QSettings("CipherLabX", "DesktopLab"); self.history: list[dict[str, str]] = []; self.worker = None
        root = QVBoxLayout(self); root.setContentsMargins(24, 20, 24, 20); root.setSpacing(14)
        header = QHBoxLayout(); title_col = QVBoxLayout(); title_col.setSpacing(3)
        title_col.addWidget(self._label("实验智能助手", "eyebrow")); title_col.addWidget(self._label("密码学实验助手", "pageTitle")); header.addLayout(title_col); header.addStretch()
        self.connection = self._label("● 未连接", "muted"); header.addWidget(self.connection)
        settings_btn = QPushButton("设置"); settings_btn.clicked.connect(self.open_settings); header.addWidget(settings_btn); root.addLayout(header)
        self.chat_scroll = QScrollArea(); self.chat_scroll.setWidgetResizable(True); self.chat_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.chat_body = QWidget(); self.chat_layout = QVBoxLayout(self.chat_body); self.chat_layout.setContentsMargins(8, 8, 8, 8); self.chat_layout.setSpacing(14); self.chat_layout.addStretch(); self.chat_scroll.setWidget(self.chat_body); root.addWidget(self.chat_scroll, 1)
        quick = QHBoxLayout(); quick.setSpacing(8)
        for text, prompt in [("解释当前实验", "请解释当前实验的原理、关键步骤和安全边界。"), ("诊断项目状态", "请诊断当前项目状态，指出已通过项、风险和下一步建议。"), ("生成实验结论", "请根据项目资料生成一段可放入实验记录的中文结论。")]:
            b = QPushButton(text); b.clicked.connect(lambda _, p=prompt: self.send_text(p)); quick.addWidget(b)
        root.addLayout(quick)
        composer = QHBoxLayout(); composer.setSpacing(10)
        self.input = QPlainTextEdit(); self.input.setPlaceholderText("输入问题，Enter 发送，Shift+Enter 换行…"); self.input.setFixedHeight(72); self.input.installEventFilter(self); composer.addWidget(self.input, 1)
        self.send_btn = QPushButton("发送"); self.send_btn.setObjectName("primary"); self.send_btn.setFixedWidth(88); self.send_btn.clicked.connect(self.send); composer.addWidget(self.send_btn)
        copy = QPushButton("复制回答"); copy.setFixedWidth(88); copy.clicked.connect(self.copy_latest); composer.addWidget(copy)
        clear = QPushButton("清空"); clear.setFixedWidth(72); clear.clicked.connect(self.clear_chat); composer.addWidget(clear); root.addLayout(composer)
        self.status = self._label("尚未发送消息", "muted"); root.addWidget(self.status)
        self.add_assistant("你好。我可以结合 Internship2 的 README、TODO、Git 状态和当前实验问题，帮你解释算法、诊断通信、整理实验结论。")

    @staticmethod
    def _label(text: str, name: str) -> QLabel:
        x = QLabel(text); x.setObjectName(name); x.setWordWrap(True); return x

    def open_settings(self):
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.connection.setText("● 配置已保存")

    def add_user(self, text: str):
        bubble = QLabel(text); bubble.setObjectName("userBubble"); bubble.setWordWrap(True); bubble.setMaximumWidth(720); bubble.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row = QHBoxLayout(); row.setContentsMargins(70, 0, 0, 0); row.addStretch(); row.addWidget(bubble); self.chat_layout.insertLayout(self.chat_layout.count() - 1, row)

    def add_assistant(self, markdown: str):
        bubble = QTextBrowser(); bubble.setObjectName("assistantBubble"); bubble.setMarkdown(markdown); bubble.setOpenExternalLinks(False); bubble.setReadOnly(True); bubble.setMinimumHeight(70); bubble.setMaximumHeight(520); bubble.setMaximumWidth(820)
        row = QHBoxLayout(); row.setContentsMargins(0, 0, 70, 0); row.addWidget(bubble); row.addStretch(); self.chat_layout.insertLayout(self.chat_layout.count() - 1, row)

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

    def send(self):
        text = self.input.toPlainText().strip()
        if text: self.send_text(text)

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
        if self.worker and self.worker.isRunning(): return
        self.input.clear(); self.add_user(text); self.history.append({"role": "user", "content": compose_prompt("explain", text, collect_context())})
        self.add_assistant("正在读取项目资料并请求助手…")
        self.send_btn.setEnabled(False); self.connection.setText("● 助手思考中…"); self.status.setText("正在读取项目资料并请求模型…")
        config = AgentConfig(self.settings.value("base_url", ""), self.settings.value("api_key", ""), self.settings.value("model", ""), self.settings.value("auth_mode", "bearer"), "Authorization")
        self.worker = AgentWorker(config, self.history.copy()); self.worker.completed.connect(self.on_answer); self.worker.failed.connect(self.on_error); self.worker.start()

    def on_answer(self, text: str):
        self._remove_last_assistant(); self.add_assistant(text); self.history.append({"role": "assistant", "content": text}); self.send_btn.setEnabled(True); self.connection.setText("● 已连接"); self.status.setText("回答完成")
        self.chat_scroll.verticalScrollBar().setValue(self.chat_scroll.verticalScrollBar().maximum())

    def on_error(self, text: str):
        self._remove_last_assistant(); self.add_assistant("**请求失败**\n\n" + text); self.send_btn.setEnabled(True); self.connection.setText("● 请求失败"); self.status.setText("请检查设置后重试")

    def clear_chat(self):
        self.history.clear()
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.layout():
                while item.layout().count():
                    child = item.layout().takeAt(0)
                    if child.widget(): child.widget().deleteLater()
                item.layout().deleteLater()
        self.add_assistant("会话已清空。你可以重新提问。")
        self.connection.setText("● 未连接"); self.status.setText("尚未发送消息")
