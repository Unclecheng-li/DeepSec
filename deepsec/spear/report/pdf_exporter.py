"""PDF export for VulnClaw reports.

Spec §5.3: consume VulnClaw's existing report (the markdown produced by
``deepsec.spear.report.generator.generate_report``) and render it to a styled PDF —
not a parallel report builder. ``reportlab`` is an optional extra
(``vulnclaw[pdf]``); importing this module is fine without it, but calling
``export_pdf`` without the extra raises a clear, actionable error.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional, Union

try:  # optional dependency
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        ListFlowable,
        ListItem,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _HAVE_REPORTLAB = True
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    _HAVE_REPORTLAB = False

_PDF_EXTRA_HINT = (
    "PDF export requires reportlab. Install the extra with: pip install 'vulnclaw[pdf]'"
)

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(.*)$")
_ORDERED_RE = re.compile(r"^\s*\d+\.\s+(.*)$")
_TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:-]+\|[\s:|-]*$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_ITALIC_RE = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
_CODE_RE = re.compile(r"`([^`]+)`")


def _inline(text: str) -> str:
    """Escape XML and apply inline markdown (bold/italic/code) -> reportlab markup."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _BOLD_RE.sub(r"<b>\1</b>", text)
    text = _CODE_RE.sub(r'<font face="Courier">\1</font>', text)
    text = _ITALIC_RE.sub(r"<i>\1</i>", text)
    return text


def _split_row(line: str) -> list[str]:
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def _build_flowables(markdown: str, styles: Any) -> list:
    body = styles["BodyText"]
    code_style = ParagraphStyle(
        "ClawCode", parent=styles["Code"], backColor=colors.whitesmoke, leftIndent=6, fontSize=8
    )
    flow: list = []
    lines = markdown.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]

        # Fenced code block
        if line.strip().startswith("```"):
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence
            if buf:
                flow.append(Preformatted("\n".join(buf), code_style))
                flow.append(Spacer(1, 4))
            continue

        # Table (consecutive pipe lines)
        if line.lstrip().startswith("|") and "|" in line.strip()[1:]:
            rows = []
            while i < n and lines[i].lstrip().startswith("|"):
                if not _TABLE_SEP_RE.match(lines[i]):
                    rows.append([_inline(c) for c in _split_row(lines[i])])
                i += 1
            if rows:
                flow.append(_make_table(rows, body))
                flow.append(Spacer(1, 6))
            continue

        # Heading
        m = _HEADING_RE.match(line)
        if m:
            level = len(m.group(1))
            style_name = f"Heading{min(level, 4)}"
            flow.append(Paragraph(_inline(m.group(2)), styles[style_name]))
            i += 1
            continue

        # Horizontal rule
        if line.strip() in ("---", "***", "___"):
            flow.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
            flow.append(Spacer(1, 4))
            i += 1
            continue

        # Bullet / ordered list (group consecutive items)
        if _BULLET_RE.match(line) or _ORDERED_RE.match(line):
            items = []
            ordered = bool(_ORDERED_RE.match(line))
            while i < n and (_BULLET_RE.match(lines[i]) or _ORDERED_RE.match(lines[i])):
                mm_ = _BULLET_RE.match(lines[i]) or _ORDERED_RE.match(lines[i])
                items.append(ListItem(Paragraph(_inline(mm_.group(1)), body)))
                i += 1
            flow.append(
                ListFlowable(items, bulletType="1" if ordered else "bullet", leftIndent=14)
            )
            flow.append(Spacer(1, 4))
            continue

        # Blank line
        if not line.strip():
            flow.append(Spacer(1, 4))
            i += 1
            continue

        # Paragraph
        flow.append(Paragraph(_inline(line), body))
        i += 1

    return flow


def _make_table(rows: list[list[str]], body: Any) -> Table:
    data = [[Paragraph(c, body) for c in row] for row in rows]
    table = Table(data, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def export_pdf(
    markdown: str, out_path: Union[str, Path], *, title: Optional[str] = None
) -> Path:
    """Render a VulnClaw markdown report to a PDF file.

    Args:
        markdown: report markdown (e.g. from ``generate_report``).
        out_path: destination ``.pdf`` path.
        title: optional document title rendered at the top.

    Raises:
        RuntimeError: if the ``[pdf]`` extra (reportlab) is not installed.
    """
    if not _HAVE_REPORTLAB:
        raise RuntimeError(_PDF_EXTRA_HINT)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()

    flow: list = []
    if title:
        flow.append(Paragraph(_inline(title), styles["Title"]))
        flow.append(Spacer(1, 6))
    flow.extend(_build_flowables(markdown, styles))

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=title or "VulnClaw Report",
    )
    doc.build(flow)
    return out
