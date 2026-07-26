"""Helpers for turning highlighted source HTML into model-readable source text."""

from __future__ import annotations

import html
import re


def clip_text(value: str, limit: int, *, marker: str = "...[truncated]...") -> str:
    text = str(value or "")
    if limit <= 0 or len(text) <= limit:
        return text
    head = max(1, limit // 2)
    tail = max(1, limit - head - len(marker) - 2)
    return f"{text[:head].rstrip()}\n{marker}\n{text[-tail:].lstrip()}"


def looks_like_highlighted_source(raw: str) -> bool:
    text = str(raw or "")
    lower = text.lower()
    if not text.strip():
        return False
    has_source_marker = any(
        marker in lower
        for marker in (
            "&lt;?php",
            "<?php",
            "highlight_file",
            "show_source",
            "unserialize",
            "eval(",
            "class&nbsp;",
            "function&nbsp;",
        )
    )
    has_highlight_markup = "<code" in lower or "<span" in lower or "<br" in lower
    return has_source_marker and has_highlight_markup


def strip_highlighted_source(raw: str) -> str:
    text = str(raw or "")
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    # Syntax highlighters wrap tokens in spans.  A closing span is not a source
    # newline; only block/code boundaries should split lines.
    text = re.sub(r"(?i)</(?:div|p|tr|li|pre|code)>", "\n", text)
    text = re.sub(r"(?is)<script\b[^>]*>.*?</script>", "\n", text)
    text = re.sub(r"(?is)<style\b[^>]*>.*?</style>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", "", text)
    text = html.unescape(text)
    text = text.replace("\xa0", " ")
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    collapsed: list[str] = []
    blank = False
    for line in lines:
        if line.strip():
            collapsed.append(line)
            blank = False
        elif not blank:
            collapsed.append("")
            blank = True
    return "\n".join(collapsed).strip()


def render_highlighted_source_block(raw: str, *, max_chars: int = 0) -> str:
    if not looks_like_highlighted_source(raw):
        return ""
    source = strip_highlighted_source(raw)
    if not source:
        return ""
    return "# Decoded highlighted source (auto)\n" + clip_text(source, max_chars)
