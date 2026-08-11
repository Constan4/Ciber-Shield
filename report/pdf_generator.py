"""
report/pdf_generator.py — Conversión de informe HTML a PDF.

Usa WeasyPrint para convertir el informe HTML generado a PDF profesional.
Si WeasyPrint no está instalado, el informe HTML sigue siendo válido
y puede abrirse directamente en el navegador o imprimirse a PDF desde él.

Instalación de WeasyPrint:
    pip install WeasyPrint
    # Ubuntu/Debian (dependencias del sistema):
    sudo apt install libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev libffi-dev
    # macOS:
    brew install cairo pango gdk-pixbuf libffi
"""

from pathlib import Path
from typing import Optional

from core.logger import get_logger

logger = get_logger(__name__)


def html_to_pdf(html_path: Path, pdf_path: Optional[Path] = None) -> Optional[Path]:
    """
    Convierte un archivo HTML a PDF usando WeasyPrint.

    Args:
        html_path: Ruta al archivo HTML de entrada.
        pdf_path:  Ruta de salida del PDF.
                   Por defecto: mismo nombre que el HTML pero con .pdf

    Returns:
        Path del PDF generado, o None si WeasyPrint no está disponible.
    """
    if not html_path.exists():
        logger.error(f"HTML no encontrado: {html_path}")
        return None

    out_path = pdf_path or html_path.with_suffix(".pdf")

    try:
        from weasyprint import HTML as WP_HTML  # noqa: N814
        logger.info(f"Convirtiendo a PDF: {html_path} → {out_path}")
        WP_HTML(filename=str(html_path)).write_pdf(str(out_path))
        size_kb = out_path.stat().st_size // 1024
        logger.info(f"PDF generado: {out_path} ({size_kb} KB)")
        return out_path

    except ImportError:
        logger.warning(
            "WeasyPrint no está instalado. No se puede generar el PDF.\n"
            "  Opciones:\n"
            "  1. pip install WeasyPrint (requiere libcairo, libpango)\n"
            "  2. Abrir el HTML en el navegador → Imprimir → Guardar como PDF\n"
            f"  Informe HTML disponible en: {html_path}"
        )
        return None

    except Exception as exc:
        logger.error(f"Error al generar PDF: {exc}")
        return None


def is_weasyprint_available() -> bool:
    """Comprueba si WeasyPrint está disponible en el sistema."""
    try:
        import weasyprint  # noqa: F401
        return True
    except ImportError:
        return False
