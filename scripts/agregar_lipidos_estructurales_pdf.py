from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


SOURCE = Path(r"C:\Users\andre\Downloads\taller_carbohidratos_estructura_nomenclatura.pdf")
OUT_DIR = Path(r"D:\Codex\osint-ai-framework\output\pdf")
APPENDIX = OUT_DIR / "paginas_lipidos_estructurales.pdf"
FINAL = OUT_DIR / "taller_carbohidratos_y_lipidos_estructura_nomenclatura.pdf"

PAGE_W, PAGE_H = letter
NAVY = colors.HexColor("#17364D")
TEAL = colors.HexColor("#1C8390")
INK = colors.HexColor("#28323C")
MUTED = colors.HexColor("#617080")
LINE = colors.HexColor("#9CB2C2")
PALE = colors.HexColor("#EAF4F5")
ROW = colors.HexColor("#EAF0F5")
WHITE = colors.white

FONT = "Arial"
FONT_BOLD = "Arial-Bold"


def register_fonts():
    pdfmetrics.registerFont(TTFont(FONT, r"C:\Windows\Fonts\arial.ttf"))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, r"C:\Windows\Fonts\arialbd.ttf"))


BODY = ParagraphStyle(
    "body", fontName=FONT, fontSize=10.5, leading=14, textColor=INK,
    alignment=TA_LEFT, spaceAfter=0,
)
SMALL = ParagraphStyle(
    "small", fontName=FONT, fontSize=8.7, leading=11.2, textColor=INK,
)
QHEAD = ParagraphStyle(
    "qhead", fontName=FONT_BOLD, fontSize=10.8, leading=13, textColor=NAVY,
)
WHITE_BOLD = ParagraphStyle(
    "whitebold", fontName=FONT_BOLD, fontSize=9.2, leading=11, textColor=WHITE,
)


def para(c, text, x, y_top, width, style=BODY):
    p = Paragraph(text, style)
    _, h = p.wrap(width, PAGE_H)
    p.drawOn(c, x, y_top - h)
    return y_top - h


def header(c, right_text="Estructura y nomenclatura"):
    c.setFillColor(NAVY)
    c.rect(0, PAGE_H - 48, PAGE_W, 48, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont(FONT_BOLD, 9.7)
    c.drawString(56, PAGE_H - 30, "BIOQUÍMICA - TALLER DE CARBOHIDRATOS Y LÍPIDOS")
    c.setFont(FONT, 8.5)
    c.drawRightString(PAGE_W - 56, PAGE_H - 30, right_text)


def footer(c, page_number):
    c.setStrokeColor(colors.HexColor("#D0D9E0"))
    c.setLineWidth(0.6)
    c.line(56, 37, PAGE_W - 56, 37)
    c.setFillColor(MUTED)
    c.setFont(FONT, 8.5)
    c.drawString(56, 24, "Sin contenidos de metabolismo")
    c.drawRightString(PAGE_W - 56, 24, f"Página {page_number}")


def section_bar(c, text, y=720):
    c.setFillColor(TEAL)
    c.rect(52, y - 34, PAGE_W - 104, 34, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont(FONT_BOLD, 15.2)
    c.drawString(63, y - 23, text)
    return y - 46


def qhead(c, number, title, y):
    return para(c, f"<b>{number}. {title}</b>", 63, y, PAGE_W - 126, QHEAD)


def response_lines(c, y, n=3, x=63, width=486, gap=18):
    c.setStrokeColor(LINE)
    c.setLineWidth(0.55)
    for i in range(n):
        c.line(x, y - i * gap, x + width, y - i * gap)
    return y - (n - 1) * gap - 8


def dashed_box(c, x, y, w, h, label=None):
    c.saveState()
    c.setStrokeColor(LINE)
    c.setLineWidth(0.8)
    c.setDash(4, 3)
    c.roundRect(x, y, w, h, 10, fill=0, stroke=1)
    c.restoreState()
    if label:
        c.setFillColor(MUTED)
        c.setFont(FONT, 8.3)
        c.drawString(x + 12, y + h - 15, label)


def draw_fatty_chain(c, x, y, segments=10, cis=False, label=""):
    c.setStrokeColor(NAVY)
    c.setLineWidth(1.8)
    pts = [(x, y)]
    for i in range(segments):
        dx = 15
        dy = 8 if i % 2 == 0 else -8
        if cis and i >= segments // 2:
            dx = 10
            dy -= 7
        pts.append((pts[-1][0] + dx, pts[-1][1] + dy))
    for i, (a, b) in enumerate(zip(pts, pts[1:])):
        c.line(a[0], a[1], b[0], b[1])
        if i == segments // 2:
            c.line(a[0], a[1] + 3, b[0], b[1] + 3)
    c.setFont(FONT_BOLD, 8.5)
    c.setFillColor(NAVY)
    c.drawString(x - 30, y - 3, "COOH")
    c.drawString(pts[-1][0] + 4, pts[-1][1] - 3, "CH3")
    if label:
        c.setFont(FONT, 8.5)
        c.setFillColor(MUTED)
        c.drawString(x, y - 30, label)


def draw_phospholipid(c, x, y):
    c.setStrokeColor(NAVY)
    c.setLineWidth(1.8)
    c.line(x, y + 26, x, y + 20)
    c.line(x, y - 4, x, y - 74)
    c.setFillColor(PALE)
    c.circle(x, y + 38, 12, fill=1, stroke=1)
    c.circle(x, y + 8, 12, fill=1, stroke=1)
    c.setFillColor(NAVY)
    c.setFont(FONT_BOLD, 7.4)
    c.drawCentredString(x, y + 35, "X")
    c.drawCentredString(x, y + 5, "PO4")
    c.setFont(FONT, 8)
    c.drawString(x + 18, y + 35, "grupo polar")
    c.drawString(x + 10, y - 10, "glicerol")
    for offset in (-8, 8):
        cx = x + offset
        cy = y - 25
        for i in range(6):
            nx = cx + (-6 if i % 2 == 0 else 6)
            ny = cy - 13
            c.line(cx, cy, nx, ny)
            cx, cy = nx, ny
    c.setFont(FONT, 8)
    c.drawString(x + 26, y - 66, "2 cadenas acilo")


def draw_triacylglycerol(c, x, y):
    c.setStrokeColor(NAVY)
    c.setLineWidth(1.6)
    c.line(x, y, x, y - 76)
    c.setFont(FONT, 8)
    c.setFillColor(NAVY)
    c.drawString(x - 20, y + 9, "glicerol")
    for j, yy in enumerate((y - 10, y - 38, y - 66), start=1):
        c.line(x, yy, x + 27, yy)
        c.setFont(FONT_BOLD, 8)
        c.drawString(x + 3, yy + 4, "O")
        c.drawString(x + 15, yy + 4, "C=O")
        start = x + 49
        c.line(x + 42, yy, start, yy)
        px, py = start, yy
        for i in range(5):
            nx = px + 12
            ny = py + (6 if i % 2 == 0 else -6)
            c.line(px, py, nx, ny)
            px, py = nx, ny
        c.setFont(FONT, 7.5)
        c.drawString(px + 3, py - 2, f"R{j}")


def page_8(c):
    header(c)
    y = section_bar(c, "IV. Estructura y nomenclatura de lípidos")
    y = qhead(c, 16, "Conceptos estructurales fundamentales", y)
    y = para(c, "Defina y diferencie: a) ácido graso saturado e insaturado; b) lípido simple y complejo; c) lípido saponificable y no saponificable; d) cadena acilo y grupo carboxilo.", 63, y - 5, 486)
    y = response_lines(c, y - 16, 4)

    y = qhead(c, 17, "Lectura de fórmulas de ácidos grasos", y - 12)
    y = para(c, "Complete la tabla. Para cada fórmula indique número total de carbonos, número de dobles enlaces, notación abreviada y, cuando corresponda, posiciones Δ y familia ω.", 63, y - 5, 486)
    data = [
        [Paragraph("<b>Fórmula condensada</b>", WHITE_BOLD), Paragraph("<b>N.º C</b>", WHITE_BOLD), Paragraph("<b>Abreviatura</b>", WHITE_BOLD), Paragraph("<b>Δ / ω</b>", WHITE_BOLD)],
        [Paragraph("CH3-(CH2)14-COOH", SMALL), "", "", ""],
        [Paragraph("CH3-(CH2)7-CH=CH-(CH2)7-COOH", SMALL), "", "", ""],
        [Paragraph("CH3-(CH2)4-CH=CH-CH2-CH=CH-(CH2)7-COOH", SMALL), "", "", ""],
    ]
    table = Table(data, colWidths=[270, 50, 90, 76], rowHeights=[27, 36, 39, 46])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD), ("FONTNAME", (0, 1), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 8.6), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.55, LINE),
        ("BACKGROUND", (0, 2), (-1, 2), ROW),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    tw, th = table.wrap(486, 200)
    table.drawOn(c, 63, y - th - 10)
    y = y - th - 25

    y = qhead(c, 18, "Configuración cis y trans", y)
    y = para(c, "Observe las dos representaciones. Identifique cuál corresponde a un doble enlace cis y cuál a trans; marque el doble enlace y describa la diferencia espacial de las cadenas.", 63, y - 4, 486)
    draw_fatty_chain(c, 110, y - 38, segments=10, cis=True, label="Estructura A")
    draw_fatty_chain(c, 350, y - 38, segments=10, cis=False, label="Estructura B")
    response_lines(c, y - 88, 2)
    footer(c, 8)
    c.showPage()


def page_9(c):
    header(c)
    y = 716
    y = qhead(c, 19, "Construcción de un triacilglicérido", y)
    y = para(c, "A partir de una molécula de glicerol y tres ácidos grasos, dibuje el triacilglicérido resultante. Numere los carbonos del glicerol, encierre los tres enlaces éster y señale qué partes proceden de cada reactivo.", 63, y - 5, 486)
    dashed_box(c, 63, 445, 486, 185, "Reactivos → producto estructural")
    c.setFillColor(NAVY)
    c.setFont(FONT, 9)
    c.drawString(88, 568, "HO-CH2-CH(OH)-CH2-OH")
    c.drawString(242, 568, "+  3 R-COOH")
    c.setFont(FONT_BOLD, 18)
    c.drawString(370, 563, "→")
    c.setFont(FONT, 8.5)
    c.setFillColor(MUTED)
    c.drawString(399, 568, "dibuje aquí")
    y = 420
    y = qhead(c, 20, "Anatomía de un fosfolípido", y)
    y = para(c, "En el esquema: a) identifique glicerol, dos cadenas acilo, fosfato y grupo polar; b) encierre los enlaces éster; c) señale la región polar y la región apolar; d) explique por qué esta molécula se clasifica como lípido complejo.", 63, y - 5, 486)
    dashed_box(c, 63, 132, 486, 210, "Rotule y complete el esquema")
    draw_phospholipid(c, 210, 280)
    c.setStrokeColor(LINE)
    c.setLineWidth(0.6)
    c.line(330, 290, 515, 290)
    c.line(330, 263, 515, 263)
    c.line(330, 236, 515, 236)
    c.line(330, 209, 515, 209)
    c.line(330, 182, 515, 182)
    footer(c, 9)
    c.showPage()


def page_10(c):
    header(c)
    y = section_bar(c, "IV. Estructura y nomenclatura de lípidos - continuación")
    y = qhead(c, 21, "Reconocimiento de familias lipídicas", y)
    y = para(c, "Para cada representación indique la familia, los componentes estructurales principales y si posee enlaces éster hidrolizables.", 63, y - 5, 486)
    data = [
        [Paragraph("<b>Representación</b>", WHITE_BOLD), Paragraph("<b>Familia</b>", WHITE_BOLD), Paragraph("<b>Componentes</b>", WHITE_BOLD), Paragraph("<b>¿Éster?</b>", WHITE_BOLD)],
        [Paragraph("Glicerol + 3 cadenas acilo", SMALL), "", "", ""],
        [Paragraph("Glicerol + 2 cadenas acilo + fosfato + grupo polar", SMALL), "", "", ""],
        [Paragraph("Ácido graso de cadena larga + alcohol de cadena larga", SMALL), "", "", ""],
        [Paragraph("Cuatro anillos fusionados con un -OH", SMALL), "", "", ""],
    ]
    table = Table(data, colWidths=[210, 85, 130, 61], rowHeights=[28, 49, 58, 58, 49])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD), ("FONTNAME", (0, 1), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 8.4), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.55, LINE),
        ("BACKGROUND", (0, 2), (-1, 2), ROW), ("BACKGROUND", (0, 4), (-1, 4), ROW),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    tw, th = table.wrap(486, 300)
    table.drawOn(c, 63, y - th - 10)
    y = y - th - 24

    y = qhead(c, 22, "Comparación estructural: reserva y membrana", y)
    y = para(c, "Compare los dos esquemas. Identifique el triacilglicérido y el fosfolípido; luego escriba tres diferencias exclusivamente estructurales: número de cadenas acilo, presencia de fosfato/grupo polar y número de enlaces éster.", 63, y - 5, 486)
    dashed_box(c, 63, 105, 486, 185, "Identifique, rotule y compare")
    draw_triacylglycerol(c, 175, 245)
    draw_phospholipid(c, 395, 238)
    c.setFont(FONT, 8)
    c.setFillColor(MUTED)
    c.drawCentredString(175, 128, "Estructura A")
    c.drawCentredString(395, 128, "Estructura B")

    c.setFillColor(PALE)
    c.setStrokeColor(colors.HexColor("#9FC8CD"))
    c.rect(54, 54, 504, 38, fill=1, stroke=1)
    para(c, "<b>Criterios de evaluación sugeridos:</b> carbohidratos, 70 %; estructura y nomenclatura de lípidos, 30 %. No se evalúan rutas metabólicas.", 63, 84, 486, SMALL)
    footer(c, 10)
    c.showPage()


def build_appendix():
    register_fonts()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(APPENDIX), pagesize=letter)
    c.setTitle("Sección de lípidos: estructura y nomenclatura")
    page_8(c)
    page_9(c)
    page_10(c)
    c.save()


def merge():
    source = PdfReader(str(SOURCE))
    appendix = PdfReader(str(APPENDIX))
    writer = PdfWriter()
    for page in source.pages:
        writer.add_page(page)
    for page in appendix.pages:
        writer.add_page(page)
    writer.add_metadata({
        "/Title": "Taller de carbohidratos y lípidos: estructura y nomenclatura",
        "/Subject": "Estructura, estereoquímica y nomenclatura de carbohidratos y lípidos",
        "/Author": "Material docente",
    })
    with FINAL.open("wb") as stream:
        writer.write(stream)


if __name__ == "__main__":
    build_appendix()
    merge()
    print(FINAL)
