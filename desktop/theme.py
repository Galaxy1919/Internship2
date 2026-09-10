from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    background: str
    surface: str
    surface_2: str
    surface_3: str
    border: str
    text: str
    muted: str
    primary: str
    primary_2: str
    success: str
    warning: str
    danger: str


DARK = Palette(
    background="#07111f",
    surface="#0d1b2a",
    surface_2="#12263a",
    surface_3="#18344b",
    border="#24445d",
    text="#edf7ff",
    muted="#91a9ba",
    primary="#37d6e8",
    primary_2="#63f0b0",
    success="#63e6a5",
    warning="#ffc857",
    danger="#ff6b6b",
)

LIGHT = Palette(
    background="#f4f8fb",
    surface="#ffffff",
    surface_2="#e8f1f6",
    surface_3="#d9e7ef",
    border="#b8ccd8",
    text="#102333",
    muted="#526b7a",
    primary="#087f8c",
    primary_2="#16794f",
    success="#16794f",
    warning="#9a6500",
    danger="#b42318",
)


def stylesheet(p: Palette) -> str:
    return f"""
    * {{ font-family: 'PingFang SC', 'Songti SC', 'Helvetica Neue'; color: {p.text}; }}
    QMainWindow, QWidget#root, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {{
        background: {p.background};
    }}
    QFrame#conversationPane {{ background: {p.surface}; border-right: 1px solid {p.border}; }}
    QFrame#chatPane {{ background: {p.background}; }}
    QFrame#inspectorPane {{ background: {p.surface}; border-left: 1px solid {p.border}; }}
    QPushButton#conversationItem {{ background: transparent; border: 0; border-radius: 10px; text-align: left; min-height: 58px; }}
    QPushButton#conversationItem:hover {{ background: {p.surface_2}; }}
    QLabel#avatar {{ background: {p.primary}; color: {p.background}; border-radius: 18px; font-size: 16px; font-weight: 800; }}
    QFrame#systemMessage {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 12px; max-width: 640px; }}
    QFrame#composer {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 12px; min-height: 44px; }}
    QLabel#userBubble {{ background: {p.primary}; color: {p.background}; border-radius: 14px; padding: 12px 16px; font-size: 14px; }}
    QTextBrowser#assistantBubble {{ background: {p.surface}; color: {p.text}; border: 1px solid {p.border}; border-radius: 14px; padding: 10px 14px; font-size: 14px; }}
    QTextBrowser#assistantBubble a {{ color: {p.primary}; }}
    QTextBrowser#assistantBubble code {{ background: {p.surface_2}; color: {p.primary_2}; }}
    QFrame.card:hover {{ border-color: {p.primary}; }}
    QLabel#brand {{ color: {p.primary}; font-size: 22px; font-weight: 800; letter-spacing: 2px; }}
    QLabel#eyebrow {{ color: {p.primary}; font-size: 11px; font-weight: 700; letter-spacing: 2px; }}
    QLabel#pageTitle {{ font-size: 30px; font-weight: 800; }}
    QLabel#heroTitle {{ font-size: 18px; font-weight: 400; }}
    QLabel#sectionTitle {{ font-size: 17px; font-weight: 700; }}
    QLabel#muted {{ color: {p.muted}; }}
    QLabel#metricValue {{ color: {p.primary}; font-size: 22px; font-weight: 750; }}
    QLabel#status {{ color: {p.success}; font-weight: 700; }}
    QLabel#warning {{ color: {p.warning}; font-weight: 700; }}
    QLabel#danger {{ color: {p.danger}; font-weight: 700; }}
    QPushButton {{
        min-height: 40px; padding: 0 16px; border: 1px solid {p.border};
        border-radius: 8px; background: {p.surface_2}; color: {p.text}; font-weight: 600;
    }}
    QPushButton:hover {{ background: {p.surface_3}; border-color: {p.primary}; }}
    QPushButton:pressed {{ background: {p.primary}; color: {p.background}; }}
    QPushButton:disabled {{ color: {p.muted}; background: {p.surface}; }}
    QPushButton#primary {{ background: {p.primary}; color: {p.background}; border: 0; }}
    QPushButton#primary:hover {{ background: {p.primary_2}; }}
    QPushButton#danger {{ color: {p.danger}; border-color: {p.danger}; }}
    QPushButton#nav {{ text-align: left; padding: 0 18px; border: 0; border-left: 3px solid transparent; border-radius: 0; background: transparent; color: {p.muted}; }}
    QPushButton#nav:hover {{ background: {p.surface_2}; color: {p.text}; }}
    QPushButton#nav[active="true"] {{ color: {p.primary}; background: {p.surface_2}; border-left-color: {p.primary}; }}
    QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{
        background: {p.surface_2}; border: 1px solid {p.border}; border-radius: 8px;
        padding: 9px 12px; selection-background-color: {p.primary};
    }}
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border: 2px solid {p.primary}; padding: 8px 11px; }}
    QComboBox QAbstractItemView {{ background: {p.surface}; border: 1px solid {p.border}; selection-background-color: {p.primary}; }}
    QProgressBar {{ background: {p.surface_2}; border: 0; border-radius: 4px; height: 8px; text-visible: false; }}
    QProgressBar::chunk {{ background: {p.primary}; border-radius: 4px; }}
    QPlainTextEdit#console {{ background: #050b13; color: {p.primary_2}; border: 1px solid {p.border}; font-family: 'Menlo', 'Monaco'; font-size: 12px; }}
    QTableWidget {{ background: {p.surface}; border: 1px solid {p.border}; gridline-color: {p.border}; alternate-background-color: {p.surface_2}; }}
    QHeaderView::section {{ background: {p.surface_2}; color: {p.muted}; border: 0; padding: 8px; font-weight: 700; }}
    QTableWidget::item:selected {{ background: {p.primary}; color: {p.background}; }}
    QScrollBar:vertical {{ width: 8px; background: {p.background}; }}
    QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 4px; min-height: 30px; }}
    QToolTip {{ background: {p.surface_3}; color: {p.text}; border: 1px solid {p.border}; padding: 5px; }}
    """
