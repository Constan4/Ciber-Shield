"""
report — Generador de informes de Ciber-Shield.

Módulos:
    html_generator.py → Informe HTML profesional con Jinja2
    pdf_generator.py  → Conversión HTML → PDF con WeasyPrint
"""

from .html_generator import HTMLReportGenerator, collect_report_data
from .pdf_generator  import html_to_pdf, is_weasyprint_available

def run_report(scan_id: int, fmt: str = "html"):
    """
    Genera un informe HTML (y opcionalmente PDF) de una auditoría.

    Args:
        scan_id: ID de la auditoría.
        fmt:     'html' | 'pdf' | 'both'

    Returns:
        Path del archivo generado (HTML o PDF).
    """
    from pathlib import Path
    gen  = HTMLReportGenerator(scan_id)
    html = gen.generate()

    if fmt in ("pdf", "both"):
        pdf = html_to_pdf(html)
        if pdf and fmt == "pdf":
            return pdf

    return html

__all__ = [
    "HTMLReportGenerator", "collect_report_data",
    "html_to_pdf", "is_weasyprint_available",
    "run_report",
]
