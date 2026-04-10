from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PDF_BG = colors.HexColor('#ffffff')
PDF_TEXT = colors.HexColor('#223043')
PDF_MUTED = colors.HexColor('#6b7788')
PDF_BLUE = colors.HexColor('#5b8fc9')
PDF_BLUE_SOFT = colors.HexColor('#edf4fb')
PDF_BLUE_PANEL = colors.HexColor('#dbe8f6')
PDF_HEADER = colors.HexColor('#f5f8fc')
PDF_BORDER = colors.HexColor('#c8d3e0')
PDF_GRID = colors.HexColor('#d7dee8')
PDF_ROW_ALT = colors.HexColor('#f8fafc')
PDF_WHITE = colors.white
PDF_GREEN = colors.HexColor('#2e7d32')
PDF_YELLOW = colors.HexColor('#b7791f')
PDF_RED = colors.HexColor('#c53030')


def _fmt_money(v: object) -> str:
    try:
        num = float(v or 0)
    except Exception:
        num = 0.0
    s = f"{num:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')
    return f"R$ {s}"


def _fmt_num(v: object) -> str:
    try:
        num = float(v or 0)
    except Exception:
        return '0'
    if abs(num - round(num)) < 0.000001:
        return f"{int(round(num))}"
    return f"{num:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')


def _status_text(status: str) -> str:
    return str(status or 'PENDENTE').strip().upper().replace('_', ' ')


def _status_color(status: str):
    st = _status_text(status)
    if st == 'PAGO':
        return PDF_GREEN
    if st == 'A PAGAR':
        return PDF_YELLOW
    return PDF_RED


def _build_styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle(
            'ExportTitle', parent=base['Heading1'], fontName='Helvetica-Bold',
            fontSize=20, leading=23, textColor=PDF_BLUE, alignment=TA_LEFT,
        ),
        'subtitle': ParagraphStyle(
            'ExportSubtitle', parent=base['BodyText'], fontName='Helvetica',
            fontSize=9.2, leading=11.5, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'kpi_label': ParagraphStyle(
            'KpiLabel', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8, leading=10, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'kpi_value': ParagraphStyle(
            'KpiValue', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=15, leading=17, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'section': ParagraphStyle(
            'SectionTitle', parent=base['Heading2'], fontName='Helvetica-Bold',
            fontSize=12.5, leading=14.5, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'small': ParagraphStyle(
            'Small', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.2, leading=10, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'small_right': ParagraphStyle(
            'SmallRight', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.2, leading=10, textColor=PDF_MUTED, alignment=TA_RIGHT,
        ),
        'label': ParagraphStyle(
            'Label', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8.2, leading=10, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'value': ParagraphStyle(
            'Value', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=10.8, leading=12.8, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'value_center': ParagraphStyle(
            'ValueCenter', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=10.8, leading=12.8, textColor=PDF_TEXT, alignment=TA_CENTER,
        ),
        'table_head': ParagraphStyle(
            'TableHead', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8.0, leading=9.5, textColor=PDF_TEXT, alignment=TA_CENTER,
        ),
        'table_cell': ParagraphStyle(
            'TableCell', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.0, leading=9.7, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'table_cell_right': ParagraphStyle(
            'TableCellRight', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.0, leading=9.7, textColor=PDF_TEXT, alignment=TA_RIGHT,
        ),
        'table_cell_bold': ParagraphStyle(
            'TableCellBold', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8.0, leading=9.7, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'note': ParagraphStyle(
            'Note', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.0, leading=10.2, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'footer': ParagraphStyle(
            'Footer', parent=base['BodyText'], fontName='Helvetica',
            fontSize=7.2, leading=9, textColor=PDF_MUTED, alignment=TA_RIGHT,
        ),
    }


def _p(text: str, style) -> Paragraph:
    return Paragraph(text, style)


def _metric_card(label: str, value: str, styles):
    table = Table(
        [[_p(escape(label), styles['kpi_label'])], [_p(escape(value), styles['kpi_value'])]],
        colWidths=[62 * mm],
    )
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_WHITE),
        ('BOX', (0, 0), (-1, -1), 0.8, PDF_BORDER),
        ('LINEBELOW', (0, 0), (-1, 0), 0.4, PDF_GRID),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    return table


def _header_footer(canvas, doc):
    canvas.saveState()
    w, _ = landscape(A4)
    canvas.setStrokeColor(PDF_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 10 * mm, w - doc.rightMargin, 10 * mm)
    canvas.setFillColor(PDF_MUTED)
    canvas.setFont('Helvetica', 7.5)
    canvas.drawString(doc.leftMargin, 6.7 * mm, 'Veipeças • Relatório de Campanhas')
    canvas.drawRightString(w - doc.rightMargin, 6.7 * mm, f'Página {canvas.getPageNumber()}')
    canvas.restoreState()


def _tipo_chip_text(tipos_resumo: list[dict] | None) -> str:
    tipos_resumo = tipos_resumo or []
    if not tipos_resumo:
        return 'Sem tipos destacados'
    return ' • '.join(f"{str(t.get('label') or '').upper()} ({int(t.get('count') or 0)})" for t in tipos_resumo)


def build_relatorio_campanhas_pdf(
    *,
    ano: int,
    mes: int,
    emps_sel: list[str],
    resumo: dict,
    emp_cards: list[dict],
) -> bytes:
    styles = _build_styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=10 * mm,
        bottomMargin=14 * mm,
        title=f'Relatório de Campanhas {mes:02d}/{ano}',
        author='OpenAI',
    )

    story = []

    header = Table([
        [
            _p(f'Relatório de Campanhas {mes:02d}/{ano}', styles['title']),
            _p(
                escape('EMPs: ' + (', '.join([str(e) for e in (emps_sel or [])]) if emps_sel else 'todas as selecionadas'))
                + '<br/>'
                + 'Modelo analítico por loja, vendedor e campanhas detalhadas.',
                styles['subtitle'],
            ),
        ]
    ], colWidths=[140 * mm, 137 * mm])
    header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_WHITE),
        ('BOX', (0, 0), (-1, -1), 0.9, PDF_BORDER),
        ('LINEBELOW', (0, 0), (-1, -1), 1.4, PDF_BLUE),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 11),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    story.append(header)
    story.append(Spacer(1, 4.5 * mm))

    status = (resumo or {}).get('status', {}) if isinstance(resumo, dict) else {}
    metric_table = Table([
        [
            _metric_card('Total geral', _fmt_money((resumo or {}).get('total_valor', 0)), styles),
            _metric_card('Pendente', _fmt_money(status.get('PENDENTE', 0)), styles),
            _metric_card('A pagar', _fmt_money(status.get('A_PAGAR', 0)), styles),
            _metric_card('Pago', _fmt_money(status.get('PAGO', 0)), styles),
        ]
    ], colWidths=[67 * mm, 67 * mm, 67 * mm, 67 * mm])
    metric_table.setStyle(TableStyle([
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(metric_table)
    story.append(Spacer(1, 4 * mm))

    note = Table([[_p(
        '<b>Leitura:</b> cada loja fica em um bloco separado. Em cada vendedor, o total a receber aparece em destaque e logo abaixo ficam as campanhas em formato de planilha.',
        styles['note'],
    )]], colWidths=[277 * mm])
    note.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_HEADER),
        ('BOX', (0, 0), (-1, -1), 0.6, PDF_BORDER),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
    ]))
    story.append(note)
    story.append(Spacer(1, 5 * mm))

    if not emp_cards:
        empty = Table([[_p('Nenhum dado encontrado para os filtros selecionados.', styles['section'])]], colWidths=[277 * mm])
        empty.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), PDF_WHITE),
            ('BOX', (0, 0), (-1, -1), 0.8, PDF_BORDER),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
        ]))
        story.append(empty)
    else:
        for emp_idx, card in enumerate(emp_cards):
            status_label = _status_text(card.get('status') or 'PENDENTE')
            emp_header = Table([
                [
                    _p(f"Loja {escape(str(card.get('emp') or '—'))}", styles['section']),
                    _p(
                        f"<b>Total:</b> {_fmt_money(card.get('total', 0))} &nbsp;&nbsp;"
                        f"<b>Vendedores:</b> {int(card.get('vendedores_count') or 0)} &nbsp;&nbsp;"
                        f"<b>Campanhas:</b> {int(card.get('campanhas_count') or 0)}",
                        styles['small_right'],
                    ),
                ],
                [
                    _p(_tipo_chip_text(card.get('tipos_resumo') or []), styles['small']),
                    _p(f"<b>Status:</b> <font color='#{_status_color(status_label).hexval()[2:]}'>{escape(status_label)}</font>", styles['small_right']),
                ],
            ], colWidths=[170 * mm, 107 * mm])
            emp_header.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), PDF_BLUE_SOFT),
                ('BOX', (0, 0), (-1, -1), 0.9, PDF_BORDER),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, PDF_BORDER),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('ALIGN', (1, 0), (1, 1), 'RIGHT'),
            ]))
            story.append(emp_header)
            story.append(Spacer(1, 2.5 * mm))

            for row in (card.get('rows') or []):
                vend_status = _status_text(row.get('status') or 'PENDENTE')
                seller_box = Table([
                    [
                        _p(escape(str(row.get('vendedor') or '—')), styles['value']),
                        _p(f"Total a receber: {_fmt_money(row.get('total', 0))}", styles['value_center']),
                        _p(f"<font color='#{_status_color(vend_status).hexval()[2:]}'><b>{escape(vend_status)}</b></font>", styles['value']),
                    ],
                    [
                        _p(
                            f"Campanhas: {int(row.get('campanhas_count') or 0)}"
                            + (f" • Tipos: {' • '.join(escape(str(t.get('short') or '')) for t in (row.get('tipos_resumo') or []))}" if row.get('tipos_resumo') else ''),
                            styles['small'],
                        ),
                        '',
                        '',
                    ],
                ], colWidths=[98 * mm, 94 * mm, 85 * mm])
                seller_box.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), PDF_WHITE),
                    ('BOX', (0, 0), (-1, -1), 0.8, PDF_BORDER),
                    ('LINEBELOW', (0, 0), (-1, 0), 0.45, PDF_GRID),
                    ('LEFTPADDING', (0, 0), (-1, -1), 9),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 9),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('ALIGN', (1, 0), (1, 0), 'CENTER'),
                    ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
                    ('SPAN', (0, 1), (2, 1)),
                ]))
                story.append(seller_box)
                story.append(Spacer(1, 1.2 * mm))

                data = [[
                    _p('Tipo', styles['table_head']),
                    _p('Campanha / item', styles['table_head']),
                    _p('Qtd / base', styles['table_head']),
                    _p('Vendeu (R$)', styles['table_head']),
                    _p('Valor (R$)', styles['table_head']),
                    _p('Status', styles['table_head']),
                ]]

                for camp in (row.get('campanhas') or []):
                    items = camp.get('itens') if isinstance(camp, dict) else None
                    label = str(camp.get('tipo_label') or camp.get('tipo_short') or camp.get('tipo') or '—').upper()
                    title = str(camp.get('titulo') or '—')
                    qtd_txt = _fmt_num(camp.get('qtd_vendida') or 0)
                    vendeu_txt = _fmt_money(camp.get('vendeu_rs') or 0)
                    valor_txt = _fmt_money(camp.get('valor') or 0)
                    st_txt = _status_text(camp.get('status') or 'PENDENTE')
                    st_color = _status_color(st_txt)
                    data.append([
                        _p(escape(label), styles['table_cell_bold']),
                        _p(escape(title), styles['table_cell_bold']),
                        _p(escape(qtd_txt), styles['table_cell_right']),
                        _p(escape(vendeu_txt), styles['table_cell_right']),
                        _p(escape(valor_txt), styles['table_cell_right']),
                        _p(f"<font color='#{st_color.hexval()[2:]}'>{escape(st_txt)}</font>", styles['table_cell_bold']),
                    ])
                    for item in (items or []):
                        item_title = f"• {str(item.get('titulo') or 'Item do combo')}"
                        item_qtd = _fmt_num(item.get('qtd_vendida') or 0)
                        item_vendeu = _fmt_money(item.get('vendeu_rs') or 0)
                        item_valor = _fmt_money(item.get('valor') or 0)
                        item_st = _status_text(item.get('status') or camp.get('status') or 'PENDENTE')
                        item_color = _status_color(item_st)
                        data.append([
                            _p('ITEM', styles['table_cell']),
                            _p(escape(item_title), styles['table_cell']),
                            _p(escape(item_qtd), styles['table_cell_right']),
                            _p(escape(item_vendeu), styles['table_cell_right']),
                            _p(escape(item_valor), styles['table_cell_right']),
                            _p(f"<font color='#{item_color.hexval()[2:]}'>{escape(item_st)}</font>", styles['table_cell']),
                        ])

                table = Table(
                    data,
                    colWidths=[23 * mm, 112 * mm, 23 * mm, 34 * mm, 34 * mm, 28 * mm],
                    repeatRows=1,
                    splitByRow=1,
                )
                ts = [
                    ('BACKGROUND', (0, 0), (-1, 0), PDF_BLUE_PANEL),
                    ('TEXTCOLOR', (0, 0), (-1, 0), PDF_TEXT),
                    ('BOX', (0, 0), (-1, -1), 0.6, PDF_BORDER),
                    ('INNERGRID', (0, 0), (-1, -1), 0.35, PDF_GRID),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('ALIGN', (2, 1), (-2, -1), 'RIGHT'),
                    ('ALIGN', (-1, 1), (-1, -1), 'CENTER'),
                ]
                for ridx in range(1, len(data)):
                    ts.append(('BACKGROUND', (0, ridx), (-1, ridx), PDF_WHITE if ridx % 2 else PDF_ROW_ALT))
                table.setStyle(TableStyle(ts))
                story.append(table)
                story.append(Spacer(1, 3.2 * mm))

            if emp_idx != len(emp_cards) - 1:
                story.append(Spacer(1, 3 * mm))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
