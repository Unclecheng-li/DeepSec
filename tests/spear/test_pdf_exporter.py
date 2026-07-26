import pytest

from deepsec.spear.report import pdf_exporter

SAMPLE_MD = """# Security Assessment

**Target:** example.com

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |

## Findings

- SQL injection in login
- Reflected XSS in search

### Detail

Some paragraph with `inline code` and **bold** text.

```
GET /admin HTTP/1.1
Host: example.com
```

---

1. First step
2. Second step
"""


@pytest.mark.skipif(not pdf_exporter._HAVE_REPORTLAB, reason="reportlab ([pdf] extra) not installed")
def test_export_pdf_writes_valid_file(tmp_path):
    out = tmp_path / "report.pdf"
    result = pdf_exporter.export_pdf(SAMPLE_MD, out, title="VulnClaw Report")
    assert result == out
    assert out.exists()
    data = out.read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 800  # non-trivial content rendered


@pytest.mark.skipif(not pdf_exporter._HAVE_REPORTLAB, reason="reportlab not installed")
def test_export_pdf_creates_parent_dirs(tmp_path):
    out = tmp_path / "nested" / "dir" / "r.pdf"
    pdf_exporter.export_pdf("# Hi\n\nbody", out)
    assert out.exists()


def test_export_pdf_without_reportlab_raises(monkeypatch):
    monkeypatch.setattr(pdf_exporter, "_HAVE_REPORTLAB", False)
    with pytest.raises(RuntimeError, match=r"vulnclaw\[pdf\]"):
        pdf_exporter.export_pdf("# x", "/tmp/should-not-exist.pdf")


def test_inline_escapes_and_formats():
    out = pdf_exporter._inline("a & b <c> **bold** `code`")
    assert "&amp;" in out and "&lt;c&gt;" in out
    assert "<b>bold</b>" in out
    assert 'face="Courier"' in out
