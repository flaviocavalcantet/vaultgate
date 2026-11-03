"""Generate the documents the extract tests read.

    pip install python-docx openpyxl python-pptx odfpy fpdf2
    python generate.py

Each document holds known PII in the places real documents put it, including the
cases naive extractors get wrong. The tests check what is found, and what is not.
"""

import pathlib

import docx
import openpyxl
import pptx
from fpdf import FPDF
from odf.opendocument import OpenDocumentText
from odf.text import P

HERE = pathlib.Path(__file__).parent
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"  # embedded, with a ToUnicode map


def word() -> None:
    d = docx.Document()
    d.sections[0].header.paragraphs[0].text = "Contact ana@example.com"
    p = d.add_paragraph("Card on file: ")
    p.add_run("4111 1111 ")  # Word splits text into runs; the card spans two
    p.add_run("1111 1111").bold = True
    table = d.add_table(rows=1, cols=2)
    table.cell(0, 0).text = "CPF"
    table.cell(0, 1).text = "529.982.247-25"
    d.save(HERE / "report.docx")

    clean = docx.Document()
    clean.add_paragraph("Quarterly report. Revenue grew 12% to 4,111,111.")
    clean.save(HERE / "clean.docx")


def excel() -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["name", "cpf", "cpf as a number"])
    ws.append(["Ana", "529.982.247-25", 52998224725])
    # A card split across four cells is not a card: cells must not run together.
    # Text cells live in the shared strings table; numbers sit in the sheet itself.
    ws.append(["4111", "1111", "1111", "1111"])
    ws.append([4111, 1111, 1111, 1111])
    wb.save(HERE / "clients.xlsx")


def powerpoint() -> None:
    deck = pptx.Presentation()
    slide = deck.slides.add_slide(deck.slide_layouts[1])
    slide.shapes.title.text = "Refund"
    slide.placeholders[1].text = "Card 5555 5555 5555 4444"
    deck.save(HERE / "slides.pptx")


def opendocument() -> None:
    doc = OpenDocumentText()
    doc.text.addElement(P(text="CPF do cliente: 529.982.247-25"))
    doc.save(HERE / "notes.odt")


def pdfs() -> None:
    def new():
        p = FPDF()
        p.add_page()
        p.add_font("DejaVu", fname=FONT)
        p.set_font("DejaVu", size=12)
        return p

    p = new()
    p.cell(0, 10, "Relatório de clientes, São Paulo", new_x="LMARGIN", new_y="NEXT")
    p.cell(0, 10, "cartão 4111 1111 1111 1111, CPF 529.982.247-25", new_x="LMARGIN", new_y="NEXT")
    p.add_page()
    p.cell(0, 10, "Second page: ana@example.com")
    p.output(HERE / "report.pdf")

    e = new()
    e.cell(0, 10, "Secret card 4111 1111 1111 1111")
    e.set_encryption(owner_password="owner", user_password="user")
    e.output(HERE / "encrypted.pdf")

    data = (HERE / "report.pdf").read_bytes()
    (HERE / "truncated.pdf").write_bytes(data[: len(data) // 2])

    # An innocent page with a file attached: the attachment is not page text.
    a = new()
    a.cell(0, 10, "Nothing to see on this page.")
    a.embed_file(basename="customers.csv", bytes=b"name;card\nAna;5555 5555 5555 4444\n")
    a.output(HERE / "attached.pdf")

    # A small PDF with a large, compressible attachment: limits must apply to what
    # the attachment expands to, not to the size of the PDF.
    big = new()
    big.cell(0, 10, "Small page, large attachment.")
    big.embed_file(basename="dump.csv", bytes=b"0" * (1 << 20) + b"\n4111 1111 1111 1111\n", compress=True)
    big.output(HERE / "big_attachment.pdf")


if __name__ == "__main__":
    word()
    excel()
    powerpoint()
    opendocument()
    pdfs()
