from __future__ import annotations

import re
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from PyQt6.QtCore import QProcess, QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QComboBox,
    QProgressBar, QStackedWidget, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

from .agent_page import AgentPage

ROOT = Path(__file__).resolve().parents[1]


def card() -> QFrame:
    w = QFrame(); w.setProperty("class", "card"); return w


def label(text: str, name: str = "muted") -> QLabel:
    x = QLabel(text); x.setObjectName(name); x.setWordWrap(True); return x


def append_console(box: QPlainTextEdit, text: str) -> None:
    if not text:
        return
    box.appendPlainText(text.rstrip())
    box.verticalScrollBar().setValue(box.verticalScrollBar().maximum())


def translate_log(text: str) -> str:
    """把现有 CLI 的稳定字段翻译成桌面端易读的中文，底层输出保持不变。"""
    replacements = {
        "READY": "服务端已就绪", "CLIENT": "客户端连接", "DH_SHARED": "DH 共享秘密",
        "SESSION": "会话指纹", "TRANSPORT": "传输密码", "CIPHERTEXT": "密文",
        "PLAINTEXT": "解密结果", "SERVER_ACK PASS": "服务端确认：通过", "FILE": "文件",
        "FILE_SIZE": "文件大小", "FILE_SAVED": "文件已保存", "DIGEST_MATCH PASS": "摘要校验：通过",
        "ECDH_SHARED": "ECDH 共享点", "PASS": "通过", "FAIL": "失败",
    }
    for old in sorted(replacements, key=len, reverse=True):
        text = text.replace(old, replacements[old])
    return text


class VerificationWorker(QThread):
    output = pyqtSignal(str)
    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(bool)

    def run(self):
        argv = [sys.executable, "-u", "run_tests.py"]
        self.output.emit(f"$ {' '.join(argv)}  (cwd={ROOT})\n")
        started = time.monotonic()
        process = None
        ok = False
        timed_out = threading.Event()

        def kill_process():
            if process is None or process.poll() is not None:
                return
            timed_out.set()
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (ProcessLookupError, OSError):
                pass

        watchdog = None
        try:
            process = subprocess.Popen(
                argv,
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                start_new_session=os.name == "posix",
            )
            watchdog = threading.Timer(1200, kill_process)
            watchdog.daemon = True
            watchdog.start()
            assert process.stdout is not None
            for line in process.stdout:
                self.output.emit(line)
                if line.startswith("[START]"):
                    parts = line.strip().split(maxsplit=3)
                    if len(parts) >= 3 and "/" in parts[1]:
                        current, total = (int(value) for value in parts[1].split("/", 1))
                        self.progress.emit(current - 1, total, " ".join(parts[2:]))
                elif line.startswith("[PASS]") or line.startswith("[FAIL]") or line.startswith("[TIMEOUT]"):
                    self.progress.emit(-1, -1, line.strip())
            process.wait(timeout=10)
            ok = process.returncode == 0 and not timed_out.is_set()
            if timed_out.is_set():
                self.output.emit("[TIMEOUT] 统一测试入口超过桌面端等待时间\n")
        except Exception as exc:
            self.output.emit(f"[FAIL] 验证中心启动失败: {exc}\n")
        finally:
            if watchdog is not None:
                watchdog.cancel()
            self.output.emit(f"验证耗时：{time.monotonic() - started:.2f}s\n")
            self.done.emit(ok)


class OverviewPage(QWidget):
    open_page = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        root = QHBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        conversations = QFrame(); conversations.setObjectName("conversationPane"); conversations.setFixedWidth(284)
        left = QVBoxLayout(conversations); left.setContentsMargins(20, 24, 16, 16); left.setSpacing(12)
        left.addWidget(label("CIPHERLAB X", "brand"))
        left.addWidget(label("本地实验工作台", "muted"))
        search = QLineEdit(); search.setPlaceholderText("搜索实验或模块"); left.addWidget(search)
        left.addWidget(label("实验会话", "eyebrow"))
        for title, subtitle, key in [
            ("算法实验", "14 个算法入口", "algorithms"),
            ("双机信道", "DH · HMAC · 文件", "dual"),
            ("攻击实验", "ElGamal k reuse", "attack"),
            ("验证中心", "真实测试结果", "verify"),
        ]:
            item = QPushButton()
            item.setObjectName("conversationItem")
            row = QHBoxLayout(item); row.setContentsMargins(12, 10, 12, 10); row.setSpacing(10)
            avatar = QLabel(title[:1]); avatar.setObjectName("avatar"); avatar.setFixedSize(36, 36); avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
            text_col = QVBoxLayout(); text_col.setSpacing(3); text_col.addWidget(label(title, "sectionTitle")); text_col.addWidget(label(subtitle, "muted"))
            row.addWidget(avatar); row.addLayout(text_col, 1)
            item.clicked.connect(lambda _, k=key: self.open_page.emit(k)); left.addWidget(item)
        left.addStretch()
        profile = card(); pl = QHBoxLayout(profile); pl.setContentsMargins(10, 10, 10, 10); pl.addWidget(label("李梦涛", "sectionTitle")); pl.addStretch(); pl.addWidget(label("在线", "status")); left.addWidget(profile)

        chat = QFrame(); chat.setObjectName("chatPane")
        center = QVBoxLayout(chat); center.setContentsMargins(28, 24, 28, 24); center.setSpacing(18)
        header = QHBoxLayout(); header.addWidget(label("实验工作台", "pageTitle")); header.addStretch(); header.addWidget(label("本地运行环境", "status")); center.addLayout(header)
        center.addWidget(label("欢迎回来，选择左侧会话开始实验。", "muted"))
        messages = QVBoxLayout(); messages.setSpacing(14)
        for who, text, tone in [
            ("系统", "密码算法模块已就绪，可直接调用原有实现。", "systemMessage"),
            ("系统", "双机信道支持 DH、传输密码、HMAC 与 ACK 验证。", "systemMessage"),
            ("系统", "攻击实验保留 ElGamal 随机数复用演示。", "systemMessage"),
        ]:
            bubble = QFrame(); bubble.setObjectName(tone); bl = QVBoxLayout(bubble); bl.setContentsMargins(16, 12, 16, 12); bl.setSpacing(5)
            bl.addWidget(label(who, "eyebrow")); bl.addWidget(label(text, "muted")); messages.addWidget(bubble)
        messages.addStretch(); center.addLayout(messages, 1)
        composer = QFrame(); composer.setObjectName("composer"); cr = QHBoxLayout(composer); cr.setContentsMargins(12, 8, 12, 8); cr.addWidget(label("选择左侧实验模块开始", "muted")); cr.addStretch(); center.addWidget(composer)

        inspector = QFrame(); inspector.setObjectName("inspectorPane"); inspector.setFixedWidth(260)
        right = QVBoxLayout(inspector); right.setContentsMargins(20, 24, 20, 20); right.setSpacing(14)
        right.addWidget(label("当前状态", "eyebrow")); right.addWidget(label("工作台概览", "sectionTitle"))
        for title, value, desc in [("算法模块", "14", "已接入原有密码实现"), ("双机协议", "READY", "等待运行真实链路"), ("测试状态", "待运行", "验证中心可执行全量测试")]:
            c = card(); c.setMinimumHeight(116)
            cl = QVBoxLayout(c); cl.setContentsMargins(16, 16, 16, 16); cl.setSpacing(7)
            cl.addWidget(label(title, "muted")); value_label = label(value, "metricValue"); value_label.setStyleSheet("font-size: 22px; font-weight: 750;"); cl.addWidget(value_label); cl.addWidget(label(desc, "muted")); right.addWidget(c)
        right.addStretch(); right.addWidget(label("所有数据来自本地仓库运行结果。", "muted"))
        root.addWidget(conversations); root.addWidget(chat, 1); root.addWidget(inspector)


class AlgorithmPage(QWidget):
    def __init__(self):
        super().__init__(); root = QVBoxLayout(self); root.setContentsMargins(28, 28, 28, 28); root.setSpacing(16)
        root.addWidget(label("ALGORITHM LAB", "eyebrow")); root.addWidget(label("单机算法实验", "pageTitle"))
        body = QHBoxLayout(); body.setSpacing(16)
        left = card(); left.setMinimumWidth(320); ll = QVBoxLayout(left); ll.setContentsMargins(20, 20, 20, 20); ll.setSpacing(12)
        ll.addWidget(label("算法目录", "sectionTitle"))
        self.alg = QComboBox(); self.alg.addItems(["aes", "des", "rsa", "ecc", "sm2", "elgamal", "dh", "rc4", "ca", "vigenere", "playfair", "multiliteral", "transposition", "md5"]); self.alg.setMinimumHeight(40); ll.addWidget(self.alg)
        ll.addWidget(label("明文 / 实验输入", "muted")); self.text = QTextEdit(); self.text.setPlainText("HELLO WORLD"); self.text.setMinimumHeight(120); ll.addWidget(self.text)
        ll.addWidget(label("密钥（支持的算法使用）", "muted")); self.key = QLineEdit("KEYWORD"); ll.addWidget(self.key)
        self.run_button = QPushButton("运行真实算法"); self.run_button.setObjectName("primary"); self.run_button.clicked.connect(self.run_demo); ll.addWidget(self.run_button); body.addWidget(left, 1)
        right = card(); rl = QVBoxLayout(right); rl.setContentsMargins(20, 20, 20, 20); rl.setSpacing(12)
        rl.addWidget(label("真实输出 / 可审计结果", "sectionTitle")); self.result = QPlainTextEdit(); self.result.setObjectName("console"); self.result.setReadOnly(True); self.result.setMaximumBlockCount(1200); rl.addWidget(self.result, 1)
        body.addWidget(right, 2); root.addLayout(body)
        root.addWidget(label("桌面端复用 DH/cipher_registry.py 的统一适配层，不替换队友算法实现。", "muted"))
        self.process = None

    def run_demo(self):
        cid = self.alg.currentText()
        self.result.setPlainText(f"正在运行：{cid} ...")
        self.run_button.setEnabled(False)
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(ROOT))
        self.process.readyReadStandardOutput.connect(self.algorithm_output)
        self.process.readyReadStandardError.connect(self.algorithm_output)
        self.process.finished.connect(self.algorithm_finished)
        self.process.start(sys.executable, [str(ROOT / "desktop" / "algorithm_runner.py"), "--cipher", cid, "--text", self.text.toPlainText(), "--key", self.key.text()])

    def algorithm_output(self):
        if not self.process:
            return
        data = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        data += bytes(self.process.readAllStandardError()).decode(errors="replace")
        append_console(self.result, translate_log(data))

    def algorithm_finished(self, code, _status):
        self.run_button.setEnabled(True)
        if code != 0:
            append_console(self.result, f"\n进程退出码：{code}")


class DualPage(QWidget):
    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self); root.setContentsMargins(28, 28, 28, 28); root.setSpacing(16)
        root.addWidget(label("SECURE CHANNEL", "eyebrow")); root.addWidget(label("双机安全信道", "pageTitle"))
        root.addWidget(label("桌面端直接启动仓库现有 decrypt_server.py / encrypt_client.py，不改变 DH 协议和队友 CLI。", "muted"))
        controls = card(); cl = QGridLayout(controls); cl.setContentsMargins(20, 20, 20, 20); cl.setSpacing(12)
        cl.addWidget(label("传输密码", "muted"), 0, 0)
        self.transport = QComboBox(); self.transport.addItems(["aes", "des", "rc4", "ca"]); self.transport.setMinimumHeight(40); cl.addWidget(self.transport, 0, 1)
        cl.addWidget(label("消息", "muted"), 0, 2)
        self.message = QLineEdit("桌面端双机通信演示"); cl.addWidget(self.message, 0, 3)
        self.run_button = QPushButton("运行真实双机链路"); self.run_button.setObjectName("primary"); self.run_button.clicked.connect(self.start); cl.addWidget(self.run_button, 1, 0, 1, 2)
        self.file_button = QPushButton("选择文件并发送")
        self.file_button.clicked.connect(self.send_file_hint)
        cl.addWidget(self.file_button, 1, 2)
        self.clear_file_button = QPushButton("清除文件")
        self.clear_file_button.clicked.connect(self.clear_file)
        cl.addWidget(self.clear_file_button, 1, 3)
        cl.setColumnStretch(1, 1); cl.setColumnStretch(3, 3)
        root.addWidget(controls)
        status = card(); sl = QHBoxLayout(status); sl.setContentsMargins(20, 16, 20, 16)
        self.status = label("● 进程未启动", "warning"); sl.addWidget(self.status); sl.addStretch(); self.hmac = label("HMAC · 等待验证", "muted"); sl.addWidget(self.hmac); root.addWidget(status)
        panels = QHBoxLayout(); panels.setSpacing(16)
        self.alice = QPlainTextEdit(); self.alice.setObjectName("console"); self.alice.setReadOnly(True); self.alice.setPlaceholderText("Alice / encrypt_client.py")
        self.bob = QPlainTextEdit(); self.bob.setObjectName("console"); self.bob.setReadOnly(True); self.bob.setPlaceholderText("Bob / decrypt_server.py")
        for title, box in [("ALICE · 加密端", self.alice), ("BOB · 解密端", self.bob)]:
            c = card(); l = QVBoxLayout(c); l.setContentsMargins(16, 16, 16, 16); l.addWidget(label(title, "sectionTitle")); l.addWidget(box); panels.addWidget(c)
        root.addLayout(panels, 1)
        self.server = None; self.client = None; self.file_path = None
        self.client_started = False
        for box in (self.alice, self.bob):
            box.setMaximumBlockCount(1500)

    def start(self):
        self.run_button.setEnabled(False); self.alice.clear(); self.bob.clear(); self.client_started = False; self.status.setText("● 正在启动 Bob，等待端口就绪...")
        self.server = QProcess(self); self.server.setWorkingDirectory(str(ROOT / "DH"))
        self.server.readyReadStandardOutput.connect(self.server_output); self.server.readyReadStandardError.connect(self.server_output)
        self.server.finished.connect(lambda *_: self.run_button.setEnabled(True)); self.server.start(sys.executable, ["decrypt_server.py"])
        append_console(self.alice, "启动 Bob / decrypt_server.py...")
        QTimer.singleShot(5000, self.start_client_if_needed)

    def start_client_if_needed(self):
        if self.server and self.server.state() != QProcess.ProcessState.NotRunning and not self.client_started:
            self.status.setText("● Bob 未及时输出 READY，尝试启动 Alice...")
            self.start_client()

    def start_client(self):
        if self.client_started:
            return
        if not self.server or self.server.state() == QProcess.ProcessState.NotRunning:
            self.status.setText("● Bob 启动失败，请查看右侧日志"); self.run_button.setEnabled(True); return
        self.client_started = True
        self.client = QProcess(self); self.client.setWorkingDirectory(str(ROOT / "DH"))
        self.client.readyReadStandardOutput.connect(self.client_output); self.client.readyReadStandardError.connect(self.client_output)
        self.client.finished.connect(lambda *_: self.run_button.setEnabled(True))
        args = ["encrypt_client.py"] + (["--file", self.file_path] if self.file_path else [self.message.text()]) + ["--transport", self.transport.currentText()]
        self.client.start(sys.executable, args); append_console(self.alice, "启动 Alice / encrypt_client.py...")

    def server_output(self):
        if not self.server: return
        data = bytes(self.server.readAllStandardOutput()).decode(errors="replace") + bytes(self.server.readAllStandardError()).decode(errors="replace")
        if data: append_console(self.bob, translate_log(data))
        if "READY" in data:
            self.status.setText("● Bob 已监听，通信进行中")
            self.start_client()
        if "PLAINTEXT" in data or "FILE_SAVED" in data: self.status.setText("● 双机通信完成"); self.hmac.setText("HMAC · 已通过")

    def client_output(self):
        if not self.client: return
        data = bytes(self.client.readAllStandardOutput()).decode(errors="replace") + bytes(self.client.readAllStandardError()).decode(errors="replace")
        if data: append_console(self.alice, translate_log(data))

    def send_file_hint(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择待传输文件")
        if path:
            self.file_path = path; self.status.setText("● 文件已选择，点击‘运行真实双机链路’发送"); append_console(self.alice, f"FILE_SELECTED {path}")

    def clear_file(self):
        self.file_path = None
        self.status.setText("● 已切换为消息发送")
        append_console(self.alice, "FILE_SELECTION_CLEARED")

    def stop(self):
        for process in (self.client, self.server):
            if process and process.state() != QProcess.ProcessState.NotRunning: process.kill()
        self.status.setText("● 双机进程已停止"); self.run_button.setEnabled(True)


class AttackPage(QWidget):
    def __init__(self):
        super().__init__(); root=QVBoxLayout(self); root.setContentsMargins(28,28,28,28); root.setSpacing(16)
        root.addWidget(label("ATTACK PLAYGROUND", "eyebrow")); root.addWidget(label("攻击实验", "pageTitle")); root.addWidget(label("基于仓库已有 recover_x_from_reused_k 实现，展示错误随机数使用如何导致私钥泄露。", "muted"))
        flow=card(); fl=QVBoxLayout(flow); fl.setContentsMargins(20,20,20,20); fl.setSpacing(14); fl.addWidget(label("ElGamal nonce reuse", "sectionTitle"));
        titles = ["两条不同消息", "错误复用同一个 k", "两次签名 r 相同", "恢复 k 与私钥 x", "伪造签名验证"]
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)  # 两列之间的水平间距
        grid.setVerticalSpacing(14)  # 两行之间的垂直间距

        for i, t in enumerate(titles):
            row, col = divmod(i, 2)  # i=0→(0,0), i=1→(0,1), i=2→(1,0) ...
            item = label("→  " + t, "heroTitle")
            grid.addWidget(item, row, col)

        fl.addLayout(grid)
        root.addWidget(flow)
        self.out=QPlainTextEdit(); self.out.setObjectName("console"); self.out.setReadOnly(True); self.out.setMaximumBlockCount(1200); root.addWidget(self.out,1)
        self.run_button=QPushButton("运行真实攻击演示"); self.run_button.setObjectName("danger"); self.run_button.clicked.connect(self.run); root.addWidget(self.run_button)
        self.process = None
    def run(self):
        self.out.setPlainText("正在运行 ElGamal 攻击演示...")
        self.run_button.setEnabled(False)
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(ROOT/"publicKey"/"Elgamal"))
        self.process.readyReadStandardOutput.connect(self.attack_output)
        self.process.readyReadStandardError.connect(self.attack_output)
        self.process.finished.connect(self.attack_finished)
        self.process.start(sys.executable, ["main.py", "--demo"])

    def attack_output(self):
        if not self.process:
            return
        data = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        data += bytes(self.process.readAllStandardError()).decode(errors="replace")
        append_console(self.out, translate_log(data))

    def attack_finished(self, code, _status):
        self.run_button.setEnabled(True)
        if code != 0:
            append_console(self.out, f"\n进程退出码：{code}")


class VerifyPage(QWidget):
    def __init__(self):
        super().__init__(); root=QVBoxLayout(self); root.setContentsMargins(28,28,28,28); root.setSpacing(16)
        root.addWidget(label("EVIDENCE CENTER", "eyebrow")); root.addWidget(label("一键验证中心", "pageTitle")); root.addWidget(label("统一执行交叉验证、官方向量、双机集成、安全信道和 C 实现测试。", "muted"))
        self.status = label("等待运行", "status")
        root.addWidget(self.status)
        self.progress = QProgressBar(); self.progress.setTextVisible(False); self.progress.setFixedHeight(8); self.progress.setRange(0, 6); self.progress.setValue(0); root.addWidget(self.progress)
        self.out=QPlainTextEdit(); self.out.setObjectName("console"); self.out.setReadOnly(True); self.out.setMaximumBlockCount(3000); root.addWidget(self.out,1); self.run=QPushButton("运行全部验收"); self.run.setObjectName("primary"); self.run.clicked.connect(self.start); root.addWidget(self.run)
    def start(self):
        self.run.setEnabled(False); self.status.setText("正在启动统一测试..."); self.progress.setValue(0); self.out.clear(); self.worker=VerificationWorker(); self.worker.output.connect(lambda text: append_console(self.out, translate_log(text))); self.worker.progress.connect(self.update_progress); self.worker.done.connect(self.finish); self.worker.start()
    def update_progress(self, current, total, text):
        if current >= 0 and total > 0:
            self.progress.setRange(0, total); self.progress.setValue(current); self.status.setText(f"正在执行：{text}")
        elif text.startswith("[PASS]"):
            self.status.setText("当前测试通过")
        elif text.startswith("[FAIL]") or text.startswith("[TIMEOUT]"):
            self.status.setText("当前测试失败")
    def finish(self, ok):
        self.run.setEnabled(True); self.progress.setValue(self.progress.maximum()); self.status.setText("全部验收：通过" if ok else "全部验收：失败"); self.out.appendPlainText("\n全部验收：通过" if ok else "\n全部验收：失败")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("CipherLab X · 密码工程实验控制台"); self.resize(1440, 900); self.setMinimumSize(1120, 720); self.dark=True
        root=QWidget(); root.setObjectName("root"); self.setCentralWidget(root); layout=QHBoxLayout(root); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)
        side=QFrame(); side.setObjectName("sidebar"); side.setFixedWidth(244); sl=QVBoxLayout(side); sl.setContentsMargins(20,28,20,24); sl.setSpacing(8)
        sl.addWidget(label("CIPHERLAB X", "brand")); sl.addWidget(label("INFORMATION SECURITY LAB", "eyebrow")); sl.addSpacing(24)
        self.stack=QStackedWidget(); self.pages={};
        self.nav_buttons={}
        for key, title, page in [("overview", "总览", OverviewPage()), ("algorithms", "算法实验", AlgorithmPage()), ("dual", "双机信道", DualPage()), ("attack", "攻击实验", AttackPage()), ("verify", "验证中心", VerifyPage()), ("agent", "智能助手", AgentPage())]:
            self.pages[key]=page; self.stack.addWidget(page); b=QPushButton(title); b.setObjectName("nav"); b.clicked.connect(lambda _,k=key:self.go(k)); self.nav_buttons[key]=b; sl.addWidget(b)
        sl.addStretch(); theme=QPushButton("切换明暗主题"); theme.clicked.connect(self.toggle_theme); sl.addWidget(theme); layout.addWidget(side); layout.addWidget(self.stack,1)
        self.pages["overview"].open_page.connect(self.go); self.apply_theme(); self.go("overview")
    def go(self,key):
        self.stack.setCurrentWidget(self.pages[key])
        for name, button in self.nav_buttons.items():
            button.setProperty("active", "true" if name == key else "false")
            button.style().unpolish(button)
            button.style().polish(button)
    def apply_theme(self):
        from .theme import DARK, stylesheet
        if hasattr(self, "qapp"):
            self.qapp.setStyleSheet(stylesheet(DARK))

    def toggle_theme(self):
        from .theme import DARK, LIGHT, stylesheet
        self.dark = not self.dark
        if hasattr(self, "qapp"):
            self.qapp.setStyleSheet(stylesheet(DARK if self.dark else LIGHT))


def build_app():
    from PyQt6.QtWidgets import QApplication
    app=QApplication.instance() or QApplication(sys.argv); win=MainWindow(); win.qapp=app
    from .theme import DARK, LIGHT, stylesheet
    app.setStyleSheet(stylesheet(DARK)); win.show(); return app,win
