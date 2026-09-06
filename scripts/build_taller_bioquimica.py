from pathlib import Path

from PIL import Image
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


ROOT = Path(r"D:\Codex\osint-ai-framework")
OUT = ROOT / "output" / "taller_bioquimica"
ASSETS = OUT / "assets"
SOURCE_IMAGE = Path(r"C:\Users\andre\.codex\generated_images\01a021bf-5c05-7010-b67b-13e73df76443\exec-5ee8f0d3-9e9e-4fcf-9b8a-bdc21103d595.png")
STUDENT = OUT / "Taller_integrador_lipidos_membranas_carbohidratos.docx"
TEACHER = OUT / "Guia_docente_taller_integrador.docx"

NAVY = "17324D"
TEAL = "167C80"
ORANGE = "D97745"
PALE_TEAL = "E9F4F3"
PALE_ORANGE = "FBEFE8"
PALE_GRAY = "F3F5F7"
INK = "24313D"
MUTED = "596873"
WHITE = "FFFFFF"


def set_cell_shading(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_cell_margins(cell, top=100, start=120, bottom=100, end=120):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for m, v in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{m}"))
        if node is None:
            node = OxmlElement(f"w:{m}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(v))
        node.set(qn("w:type"), "dxa")


def set_table_geometry(table, widths_dxa, indent=120):
    table.autofit = False
    tbl_pr = table._tbl.tblPr
    tbl_w = tbl_pr.find(qn("w:tblW"))
    if tbl_w is None:
        tbl_w = OxmlElement("w:tblW")
        tbl_pr.append(tbl_w)
    tbl_w.set(qn("w:w"), str(sum(widths_dxa)))
    tbl_w.set(qn("w:type"), "dxa")
    tbl_ind = tbl_pr.find(qn("w:tblInd"))
    if tbl_ind is None:
        tbl_ind = OxmlElement("w:tblInd")
        tbl_pr.append(tbl_ind)
    tbl_ind.set(qn("w:w"), str(indent))
    tbl_ind.set(qn("w:type"), "dxa")
    grid = table._tbl.tblGrid
    for child in list(grid):
        grid.remove(child)
    for width in widths_dxa:
        col = OxmlElement("w:gridCol")
        col.set(qn("w:w"), str(width))
        grid.append(col)
    for row in table.rows:
        for idx, cell in enumerate(row.cells):
            tc_pr = cell._tc.get_or_add_tcPr()
            tc_w = tc_pr.find(qn("w:tcW"))
            if tc_w is None:
                tc_w = OxmlElement("w:tcW")
                tc_pr.append(tc_w)
            tc_w.set(qn("w:w"), str(widths_dxa[idx]))
            tc_w.set(qn("w:type"), "dxa")
            set_cell_margins(cell)


def set_font(run, size=None, bold=None, color=None, italic=None, name="Aptos"):
    run.font.name = name
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), name)
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), name)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    if color is not None:
        run.font.color.rgb = RGBColor.from_string(color)


def set_repeat_table_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    hdr = OxmlElement("w:tblHeader")
    hdr.set(qn("w:val"), "true")
    tr_pr.append(hdr)


def keep_row_together(row):
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def add_page_field(paragraph):
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = paragraph.add_run("Página ")
    set_font(run, 8.5, color=MUTED)
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), "PAGE")
    paragraph._p.append(fld)


def configure_document(doc, teacher=False):
    sec = doc.sections[0]
    sec.page_width = Inches(8.5)
    sec.page_height = Inches(11)
    sec.top_margin = Inches(0.62)
    sec.bottom_margin = Inches(0.62)
    sec.left_margin = Inches(0.68)
    sec.right_margin = Inches(0.68)
    sec.header_distance = Inches(0.3)
    sec.footer_distance = Inches(0.3)

    styles = doc.styles
    normal = styles["Normal"]
    normal.font.name = "Aptos"
    normal._element.rPr.rFonts.set(qn("w:ascii"), "Aptos")
    normal._element.rPr.rFonts.set(qn("w:hAnsi"), "Aptos")
    normal.font.size = Pt(9.2 if not teacher else 10)
    normal.font.color.rgb = RGBColor.from_string(INK)
    normal.paragraph_format.space_after = Pt(4)
    normal.paragraph_format.line_spacing = 1.08

    for name, size, color, before, after in (
        ("Title", 25, NAVY, 0, 4),
        ("Subtitle", 11.5, MUTED, 0, 8),
        ("Heading 1", 15, NAVY, 10, 5),
        ("Heading 2", 11.5, TEAL, 8, 3),
        ("Heading 3", 10, ORANGE, 6, 2),
    ):
        st = styles[name]
        st.font.name = "Aptos Display" if name in ("Title", "Heading 1") else "Aptos"
        st._element.rPr.rFonts.set(qn("w:ascii"), st.font.name)
        st._element.rPr.rFonts.set(qn("w:hAnsi"), st.font.name)
        st.font.size = Pt(size)
        st.font.bold = name != "Subtitle"
        st.font.color.rgb = RGBColor.from_string(color)
        st.paragraph_format.space_before = Pt(before)
        st.paragraph_format.space_after = Pt(after)
        st.paragraph_format.keep_with_next = True

    hdr = sec.header.paragraphs[0]
    hdr.text = "BIOQUÍMICA · QUÍMICA FARMACÉUTICA"
    hdr.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    set_font(hdr.runs[0], 8, bold=True, color=TEAL)
    add_page_field(sec.footer.paragraphs[0])


def set_columns(section, num=2, space=360):
    sect_pr = section._sectPr
    cols = sect_pr.find(qn("w:cols"))
    if cols is None:
        cols = OxmlElement("w:cols")
        sect_pr.append(cols)
    cols.set(qn("w:num"), str(num))
    cols.set(qn("w:space"), str(space))


def add_col_break(doc):
    p = doc.add_paragraph()
    r = p.add_run()
    br = OxmlElement("w:br")
    br.set(qn("w:type"), "column")
    r._r.append(br)


def add_label_line(doc, label, length=36):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    r = p.add_run(f"{label}: ")
    set_font(r, 9, bold=True, color=NAVY)
    r = p.add_run("_" * length)
    set_font(r, 9, color=MUTED)
    return p


def add_callout(doc, title, text, fill=PALE_TEAL):
    table = doc.add_table(rows=1, cols=1)
    set_table_geometry(table, [4200], indent=0)
    keep_row_together(table.rows[0])
    cell = table.cell(0, 0)
    set_cell_shading(cell, fill)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    p = cell.paragraphs[0]
    r = p.add_run(title + " ")
    set_font(r, 9.2, bold=True, color=TEAL)
    r = p.add_run(text)
    set_font(r, 9.2, color=INK)
    return table


def add_question(doc, number, prompt, points=None):
    p = doc.add_paragraph()
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(2)
    r = p.add_run(f"{number}. ")
    set_font(r, 9.4, bold=True, color=ORANGE)
    r = p.add_run(prompt)
    set_font(r, 9.4, bold=True, color=INK)
    if points:
        r = p.add_run(f"  [{points} pt]")
        set_font(r, 8.2, bold=True, color=TEAL)
    return p


def add_response_lines(doc, count=3):
    for _ in range(count):
        p = doc.add_paragraph("________________________________________________________________")
        p.paragraph_format.space_after = Pt(1)
        p.paragraph_format.line_spacing = 0.9
        set_font(p.runs[0], 7.2, color="9AA5AD")


def add_small_table(doc, headers, rows, widths):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    set_table_geometry(table, widths, indent=0)
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        set_cell_shading(cell, NAVY)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        set_font(r, 8, bold=True, color=WHITE)
    set_repeat_table_header(table.rows[0])
    for ridx, row in enumerate(rows):
        cells = table.add_row().cells
        for i, value in enumerate(row):
            if ridx % 2:
                set_cell_shading(cells[i], PALE_GRAY)
            p = cells[i].paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(str(value))
            set_font(r, 8, color=INK)
    set_table_geometry(table, widths, indent=0)
    return table


def crop_assets():
    ASSETS.mkdir(parents=True, exist_ok=True)
    image = Image.open(SOURCE_IMAGE)
    w, h = image.size
    crops = {
        "membrana.png": (0, 100, int(w * 0.36), h - 100),
        "transporte_glucosa.png": (int(w * 0.355), 70, int(w * 0.635), h - 55),
        "liposoma_micela.png": (int(w * 0.65), 70, w, h - 70),
    }
    for name, box in crops.items():
        image.crop(box).save(ASSETS / name)


def add_picture(doc, path, caption, width=2.85):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    run = p.add_run()
    run.add_picture(str(path), width=Inches(width))
    inline = run._r.xpath(".//wp:inline")
    if inline:
        doc_pr = inline[0].find(qn("wp:docPr"))
        if doc_pr is not None:
            doc_pr.set("descr", caption)
    c = doc.add_paragraph(caption)
    c.alignment = WD_ALIGN_PARAGRAPH.CENTER
    c.paragraph_format.space_after = Pt(5)
    set_font(c.add_run() if not c.runs else c.runs[0], 7.7, italic=True, color=MUTED)


def build_student():
    doc = Document()
    configure_document(doc)
    p = doc.add_paragraph(style="Title")
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.add_run("Taller integrador")
    sp = doc.add_paragraph(style="Subtitle")
    sp.add_run("Lípidos, membranas y carbohidratos · Química Farmacéutica")
    add_label_line(doc, "Nombre", 42)
    info = doc.add_table(rows=1, cols=3)
    set_table_geometry(info, [3000, 3000, 3000], indent=0)
    for cell, text in zip(info.rows[0].cells, ["Grupo: __________", "Fecha: __________", "Tiempo sugerido: 90 min"]):
        set_cell_shading(cell, PALE_GRAY)
        r = cell.paragraphs[0].add_run(text)
        set_font(r, 8.5, bold=True, color=NAVY)
    add_callout(doc, "Propósito.", "Resolver situaciones bioquímicas propias del ámbito farmacéutico usando relaciones entre estructura, propiedades y función. Se evaluará la justificación, no solo la respuesta final.")
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(5)
    r = p.add_run("Indicaciones: ")
    set_font(r, 9, bold=True, color=NAVY)
    r = p.add_run("trabaje en parejas; escriba supuestos cuando falten datos; use vocabulario bioquímico; los esquemas pueden anotarse directamente. Puntaje total: 50 puntos.")
    set_font(r, 9, color=INK)

    sec = doc.add_section(WD_SECTION.CONTINUOUS)
    sec.top_margin = Inches(0.62)
    sec.bottom_margin = Inches(0.62)
    sec.left_margin = Inches(0.68)
    sec.right_margin = Inches(0.68)
    sec.header_distance = Inches(0.3)
    sec.footer_distance = Inches(0.3)
    set_columns(sec, 2, 360)

    doc.add_paragraph("ESTACIÓN 1 · MEMBRANA BAJO PRESIÓN", style="Heading 1")
    add_callout(doc, "Caso.", "Un lote de células usadas para expresar una proteína terapéutica se conserva a 10 °C. A las 24 h disminuye el transporte de nutrientes y aumenta la fragilidad celular.", PALE_ORANGE)
    add_small_table(doc, ["Lípido", "Lote A", "Lote B"], [
        ("AG saturados", "58 %", "31 %"),
        ("AG insaturados", "24 %", "49 %"),
        ("Colesterol", "18 %", "20 %"),
    ], [1800, 1200, 1200])
    add_question(doc, "1a", "Prediga cuál lote mantendrá mejor la fluidez a 10 °C. Explique usando empaquetamiento y punto de fusión.", 4)
    add_response_lines(doc, 4)
    add_question(doc, "1b", "Si la temperatura sube a 40 °C, ¿qué función amortiguadora tendría el colesterol? Evite responder solo “da estabilidad”.", 3)
    add_response_lines(doc, 3)
    add_question(doc, "1c", "Proponga un cambio de composición que mejore el lote más vulnerable sin volver la membrana excesivamente permeable.", 3)
    add_response_lines(doc, 3)
    add_picture(doc, ASSETS / "membrana.png", "Figura 1. Modelo simplificado de una membrana; identifique sus componentes.")
    add_question(doc, "1d", "Sobre la figura, marque una región polar, una apolar, una proteína integral y moléculas de colesterol. Luego relacione cada una con una propiedad de la membrana.", 4)
    add_response_lines(doc, 2)

    add_col_break(doc)
    doc.add_paragraph("ESTACIÓN 2 · EL VIAJE DE LA GLUCOSA", style="Heading 1")
    add_picture(doc, ASSETS / "transporte_glucosa.png", "Figura 2. Secuencia de transporte de un monosacárido a través de una proteína de membrana.")
    add_question(doc, "2a", "La figura representa difusión facilitada. Escriba tres evidencias del esquema que apoyen esa clasificación y una característica que la diferencie de la difusión simple.", 4)
    add_response_lines(doc, 4)
    add_question(doc, "2b", "Un análogo de glucosa compite por el mismo transportador. Prediga qué ocurre con la velocidad de entrada de glucosa y explique el resultado en términos de saturación y competencia.", 3)
    add_response_lines(doc, 3)
    add_question(doc, "2c", "Si la célula necesita acumular glucosa contra gradiente, ¿qué cambio de mecanismo sería necesario? Indique la fuente inmediata o indirecta de energía.", 3)
    add_response_lines(doc, 3)

    doc.add_paragraph("ESTACIÓN 3 · IDENTIDAD DE LOS AZÚCARES", style="Heading 1")
    add_callout(doc, "Datos del laboratorio.", "Tres soluciones incoloras contienen glucosa, sacarosa o lactosa. Benedict es positivo para A y C; B se vuelve positivo solo después de hidrólisis ácida. A no se hidroliza. C produce glucosa y galactosa.")
    add_question(doc, "3a", "Asigne A, B y C. Justifique cada asignación con poder reductor y productos de hidrólisis.", 4)
    add_response_lines(doc, 4)
    add_question(doc, "3b", "Indique el tipo general de enlace glucosídico de la sacarosa y explique por qué no es reductora.", 3)
    add_response_lines(doc, 3)

    doc.add_paragraph("ESTACIÓN 4 · DECISIÓN DE FORMULACIÓN", style="Heading 1")
    add_callout(doc, "Caso.", "Se diseña un fármaco para administración oral. La molécula X tiene un anillo aromático, dos grupos hidroxilo y no posee carga a pH intestinal. La molécula Y tiene varios hidroxilos y una amina protonada. Ambas son estables en el intestino.", PALE_ORANGE)
    add_question(doc, "4a", "¿Cuál tendría mayor probabilidad de atravesar la bicapa por difusión simple? Compare polaridad, carga y partición en la fase lipídica.", 4)
    add_response_lines(doc, 4)
    add_question(doc, "4b", "Para la molécula con menor permeabilidad, proponga una estrategia farmacéutica: transportador, profármaco o sistema vesicular. Explique el principio bioquímico.", 4)
    add_response_lines(doc, 5)

    doc.add_paragraph("ESTACIÓN 5 · ¿LIPOSOMA O MICELA?", style="Heading 1")
    add_picture(doc, ASSETS / "liposoma_micela.png", "Figura 3. Dos agregados anfipáticos en medio acuoso.")
    add_question(doc, "5a", "Identifique el liposoma y la micela. Dibuje dónde ubicaría un fármaco hidrofílico y uno hidrofóbico en cada sistema.", 4)
    add_response_lines(doc, 3)
    add_question(doc, "5b", "El principio activo se degrada en agua, pero se disuelve bien en lípidos. Elija el sistema más conveniente y señale una limitación que el formulador debería controlar.", 3)
    add_response_lines(doc, 3)

    doc.add_paragraph("ESTACIÓN 6 · DEL ENLACE AL SÍNTOMA", style="Heading 1")
    add_callout(doc, "Caso.", "Una paciente presenta distensión y diarrea después de consumir leche. La glucemia no aumenta como se esperaba y se detecta mayor carga osmótica en el colon.")
    add_question(doc, "6a", "Construya una cadena causal de cuatro pasos desde la enzima deficiente hasta la diarrea osmótica. Incluya el enlace que no se rompe y el destino bacteriano del azúcar.", 4)
    add_response_lines(doc, 5)
    add_question(doc, "6b", "¿Por qué una bebida con glucosa y galactosa libres produciría una respuesta diferente? Relacione digestión, absorción y gradiente osmótico.", 3)
    add_response_lines(doc, 4)

    doc.add_paragraph("CIERRE · ARGUMENTO PROFESIONAL", style="Heading 1")
    add_question(doc, "7", "Un compañero afirma: “Los carbohidratos son hidrofílicos, por eso siempre atraviesan fácilmente la membrana”. Redacte una refutación de 80–100 palabras usando, como mínimo, tamaño molecular, polaridad, núcleo hidrofóbico y proteínas de transporte.", 4)
    add_response_lines(doc, 8)

    add_callout(doc, "Antes de entregar.", "Revise que cada predicción tenga una razón molecular, que diferencie transporte de permeabilidad y que no confunda micela con liposoma.", PALE_GRAY)
    doc.core_properties.title = "Taller integrador: lípidos, membranas y carbohidratos"
    doc.core_properties.subject = "Bioquímica para Química Farmacéutica"
    doc.core_properties.author = "Docencia de Bioquímica"
    doc.save(STUDENT)


def add_answer(doc, label, text, criteria=None):
    p = doc.add_paragraph(style="Heading 2")
    p.add_run(label)
    p = doc.add_paragraph(text)
    if criteria:
        p = doc.add_paragraph()
        r = p.add_run("Criterio mínimo: ")
        set_font(r, 9.5, bold=True, color=TEAL)
        r = p.add_run(criteria)
        set_font(r, 9.5, color=INK)


def build_teacher():
    doc = Document()
    configure_document(doc, teacher=True)
    doc.add_paragraph("Guía docente", style="Title")
    doc.add_paragraph("Solucionario orientativo · Taller integrador de lípidos, membranas y carbohidratos", style="Subtitle")
    add_callout(doc, "Uso sugerido.", "Las respuestas no tienen que coincidir palabra por palabra. Asigne el puntaje por la calidad del vínculo entre estructura, propiedad y función. Acepte supuestos explícitos y científicamente coherentes.")
    doc.add_paragraph("Clave de respuestas", style="Heading 1")
    add_answer(doc, "1a (4 pt)", "El lote B conservará mejor la fluidez: su mayor proporción de ácidos grasos insaturados introduce curvaturas cis, reduce el empaquetamiento y disminuye las interacciones de Van der Waals y el punto de transición.", "Predicción correcta (1); empaquetamiento (1); insaturación/punto de fusión (2).")
    add_answer(doc, "1b (3 pt)", "A temperatura alta, el colesterol restringe el movimiento excesivo de las colas y reduce la permeabilidad. A temperatura baja, impide el empaquetamiento ordenado. Por eso amortigua cambios de fluidez en ambos sentidos.", "Explica restricción a alta temperatura y efecto amortiguador, no solo 'estabilidad'.")
    add_answer(doc, "1c–1d (7 pt)", "Una respuesta viable es aumentar moderadamente fosfolípidos con cadenas cis insaturadas y ajustar colesterol, evitando un exceso que eleve permeabilidad. En la figura: cabezas = zona polar; colas = núcleo apolar; proteína que cruza la bicapa = integral; estructuras naranjas = colesterol. Debe relacionar ubicación con función.")
    add_answer(doc, "2a (4 pt)", "Hay proteína transportadora, cambio conformacional y movimiento a favor del gradiente sin indicación de ATP. A diferencia de la difusión simple, es específica y saturable, y puede sufrir competencia.")
    add_answer(doc, "2b–2c (6 pt)", "El análogo reduce la velocidad de entrada al ocupar el transportador; el efecto depende de las concentraciones y de la afinidad. Para acumular contra gradiente se requiere transporte activo: primario con ATP o secundario acoplado a un gradiente iónico previamente mantenido con energía.")
    add_answer(doc, "3a–3b (7 pt)", "A = glucosa; B = sacarosa; C = lactosa. Glucosa y lactosa son reductoras; la sacarosa se vuelve positiva tras hidrólisis. La lactosa genera glucosa y galactosa. En sacarosa, el enlace une ambos carbonos anoméricos (α1↔β2), por lo que no queda un grupo hemiacetal libre.")
    add_answer(doc, "4a–4b (8 pt)", "X es más compatible con difusión simple porque es neutra y menos polar que Y. Y, protonada y con varios hidroxilos, tiene alto costo energético para entrar al núcleo apolar. Se acepta transportador específico, profármaco que enmascare grupos polares o sistema vesicular, siempre que se explique cómo mejora solubilidad, partición o entrega.")
    add_answer(doc, "5a–5b (7 pt)", "El agregado grande con compartimento acuoso y bicapa es el liposoma; el pequeño, con núcleo hidrofóbico y monocapa, es la micela. Un fármaco hidrofílico puede ir en el lumen del liposoma; uno hidrofóbico, en la bicapa o núcleo micelar. Para un activo lipófilo e inestable en agua son defendibles ambos, pero debe justificarse y mencionar estabilidad, fuga, tamaño, oxidación o liberación como limitación.")
    add_answer(doc, "6a–6b (7 pt)", "Deficiencia de lactasa → no se rompe el enlace β(1→4) de la lactosa → permanece soluto osmóticamente activo y llega al colon → fermentación bacteriana y retención de agua, con gas y diarrea. Glucosa y galactosa libres no requieren hidrólisis y pueden absorberse mediante transportadores, reduciendo la carga luminal.")
    add_answer(doc, "7 (4 pt)", "Debe refutar la generalización: la hidrofilia favorece la solubilidad acuosa, pero dificulta atravesar el núcleo hidrofóbico. Los monosacáridos son polares y relativamente grandes frente a gases o moléculas lipófilas, por lo que dependen de transportadores. Se valora un argumento coherente y dentro de la extensión.")
    doc.add_paragraph("Rúbrica transversal", style="Heading 1")
    add_small_table(doc, ["Nivel", "Descripción"], [
        ("Completo", "Predice, usa evidencia y explica el mecanismo molecular."),
        ("Parcial", "Respuesta correcta con explicación incompleta o vocabulario impreciso."),
        ("Insuficiente", "Afirmación memorística, contradictoria o sin relación causal."),
    ], [1500, 7860])
    doc.core_properties.title = "Guía docente del taller integrador"
    doc.core_properties.author = "Docencia de Bioquímica"
    doc.save(TEACHER)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    crop_assets()
    build_student()
    build_teacher()
    print(STUDENT)
    print(TEACHER)
