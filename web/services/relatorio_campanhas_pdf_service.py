from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PDF_BG = colors.HexColor('#0d0d10')
PDF_PANEL = colors.HexColor('#14161b')
PDF_PANEL_2 = colors.HexColor('#1a1d24')
PDF_ORANGE = colors.HexColor('#ff9800')
PDF_ORANGE_SOFT = colors.HexColor('#ffb347')
PDF_WHITE = colors.HexColor('#f5f5f7')
PDF_MUTED = colors.HexColor('#b8bcc6')
PDF_GREEN = colors.HexColor('#26a269')
PDF_YELLOW = colors.HexColor('#f4c430')
PDF_RED = colors.HexColor('#d64545')
PDF_GRID = colors.HexColor('#313744')


def _fmt_money(v: object) -> str:
    try:
        num = float(v or 0)
    except Exception:
        num = 0.0
    s = f"{num:,.2f}"
    s = s.replace(',', 'X').replace('.', ',').replace('X', '.')
    return f"R$ {s}"


def _fmt_num(v: object) -> str:
    try:
        num = float(v or 0)
    except Exception:
        return '0'
    if abs(num - round(num)) < 0.000001:
        return f"{int(round(num))}"
    s = f"{num:,.2f}"
    return s.replace(',', 'X').replace('.', ',').replace('X', '.')


def _status_color(status: str):
    st = str(status or 'PENDENTE').strip().upper()
    if st == 'PAGO':
        return PDF_GREEN
    if st == 'A_PAGAR':
        return PDF_YELLOW
    if st == 'PENDENTE':
        return PDF_RED
    return PDF_ORANGE_SOFT


def _build_styles():
    base = getSampleStyleSheet()
    styles = {
        'title': ParagraphStyle(
            'ExportTitle', parent=base['Heading1'], fontName='Helvetica-Bold',
            fontSize=20, leading=24, textColor=PDF_WHITE, alignment=TA_LEFT, spaceAfter=0,
        ),
        'subtitle': ParagraphStyle(
            'ExportSubtitle', parent=base['BodyText'], fontName='Helvetica',
            fontSize=9.5, leading=12, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'kpi_label': ParagraphStyle(
            'KpiLabel', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8, leading=10, textColor=PDF_ORANGE_SOFT, alignment=TA_LEFT,
        ),
        'kpi_value': ParagraphStyle(
            'KpiValue', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=14, leading=16, textColor=PDF_WHITE, alignment=TA_LEFT,
        ),
        'section': ParagraphStyle(
            'SectionTitle', parent=base['Heading2'], fontName='Helvetica-Bold',
            fontSize=12.5, leading=15, textColor=PDF_WHITE, alignment=TA_LEFT,
        ),
        'small': ParagraphStyle(
            'Small', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.2, leading=10, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'label': ParagraphStyle(
            'Label', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8.6, leading=10, textColor=PDF_ORANGE_SOFT, alignment=TA_LEFT,
        ),
        'value': ParagraphStyle(
            'Value', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=11, leading=13, textColor=PDF_WHITE, alignment=TA_LEFT,
        ),
        'table_cell': ParagraphStyle(
            'TableCell', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.1, leading=10, textColor=PDF_WHITE, alignment=TA_LEFT,
        ),
        'table_cell_right': ParagraphStyle(
            'TableCellRight', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.1, leading=10, textColor=PDF_WHITE, alignment=TA_RIGHT,
        ),
        'table_cell_bold': ParagraphStyle(
            'TableCellBold', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8.1, leading=10, textColor=PDF_WHITE, alignment=TA_LEFT,
        ),
        'table_head': ParagraphStyle(
            'TableHead', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=8.2, leading=10, textColor=PDF_WHITE, alignment=TA_CENTER,
        ),
        'footer': ParagraphStyle(
            'Footer', parent=base['BodyText'], fontName='Helvetica',
            fontSize=7.5, leading=9, textColor=PDF_MUTED, alignment=TA_RIGHT,
        ),
        'note': ParagraphStyle(
            'Note', parent=base['BodyText'], fontName='Helvetica',
            fontSize=8.0, leading=10.2, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
    }
    return styles


def _p(text: str, style) -> Paragraph:
    return Paragraph(text, style)


def _metric_card(label: str, value: str, styles):
    t = Table(
        [[_p(escape(label), styles['kpi_label'])], [_p(escape(value), styles['kpi_value'])]],
        colWidths=[62 * mm],
    )
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_PANEL),
        ('BOX', (0, 0), (-1, -1), 0.8, PDF_ORANGE),
        ('ROUNDEDCORNERS', [8, 8, 8, 8]),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    return t


def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = landscape(A4)
    canvas.setStrokeColor(PDF_ORANGE)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 10 * mm, w - doc.rightMargin, 10 * mm)
    canvas.setFillColor(PDF_MUTED)
    canvas.setFont('Helvetica', 7.5)
    canvas.drawRightString(w - doc.rightMargin, 6.7 * mm, f'Página {canvas.getPageNumber()}')
    canvas.restoreState()


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
        author='ChatGPT',
    )

    story = []

    header = Table([
        [
            _p(f'Relatório de fechamento - {mes:02d}/{ano}', styles['title']),
            _p(
                escape('EMPs: ' + (', '.join([str(e) for e in (emps_sel or [])]) if emps_sel else 'todas as selecionadas'))
                + '<br/>'
                + 'Consolidado por loja, vendedor e campanhas detalhadas.',
                styles['subtitle'],
            ),
        ]
    ], colWidths=[277 * mm])
    header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_BG),
        ('BOX', (0, 0), (-1, -1), 1, PDF_ORANGE),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(header)
    story.append(Spacer(1, 5 * mm))

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
        ('BACKGROUND', (0, 0), (-1, -1), PDF_BG),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(metric_table)
    story.append(Spacer(1, 4 * mm))

    note_text = (
        '<b>Leitura:</b> cada loja é exibida em um bloco próprio. Em cada vendedor, o valor destacado é o total a receber na competência. '
        'Logo abaixo ficam as campanhas detalhadas, com base, vendido, valor e status.'
    )
    note = Table([[_p(note_text, styles['note'])]], colWidths=[277 * mm])
    note.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_PANEL_2),
        ('BOX', (0, 0), (-1, -1), 0.6, PDF_GRID),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(note)
    story.append(Spacer(1, 5 * mm))

    if not emp_cards:
        empty = Table([[_p('Nenhum dado encontrado para os filtros selecionados.', styles['section'])]], colWidths=[277 * mm])
        empty.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), PDF_PANEL),
            ('BOX', (0, 0), (-1, -1), 0.8, PDF_ORANGE),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
        ]))
        story.append(empty)
    else:
        for idx, card in enumerate(emp_cards):
            status_label = str(card.get('status') or 'PENDENTE').replace('_', ' ')
            tipos_resumo = card.get('tipos_resumo') or []
            tipos_txt = ' • '.join(f"{t.get('label')} ({int(t.get('count') or 0)})" for t in tipos_resumo) or 'Sem detalhes adicionais'

            emp_header = Table([
                [
                    _p(f"Loja {escape(str(card.get('emp') or '—'))}", styles['section']),
                    _p(
                        f"<b>Total:</b> {_fmt_money(card.get('total', 0))}&nbsp;&nbsp;&nbsp;"
                        f"<b>Vendedores:</b> {int(card.get('vendedores_count') or 0)}&nbsp;&nbsp;&nbsp;"
                        f"<b>Campanhas:</b> {int(card.get('campanhas_count') or 0)}&nbsp;&nbsp;&nbsp;"
                        f"<b>Status:</b> {escape(status_label)}",
                        styles['small'],
                    ),
                ],
                [
                    _p(escape(tipos_txt), styles['small']),
                    '',
                ]
            ], colWidths=[145 * mm, 132 * mm])
            emp_header.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), PDF_PANEL),
                ('BOX', (0, 0), (-1, -1), 0.8, PDF_ORANGE),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('SPAN', (0, 1), (1, 1)),
                ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ]))
            story.append(emp_header)
            story.append(Spacer(1, 2.5 * mm))

            for row in (card.get('rows') or []):
                vend_status = str(row.get('status') or 'PENDENTE').replace('_', ' ')
                vend_header = Table([
                    [
                        _p(escape(str(row.get('vendedor') or '—')), styles['value']),
                        _p(f"<b>Total a receber:</b> {_fmt_money(row.get('total', 0))}", styles['value']),
                        _p(f"<b>Status:</b> {escape(vend_status)}", styles['label']),
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
                ], colWidths=[92 * mm, 96 * mm, 89 * mm])
                vend_header.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), PDF_PANEL_2),
                    ('BOX', (0, 0), (-1, -1), 0.6, PDF_GRID),
                    ('LEFTPADDING', (0, 0), (-1, -1), 9),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 9),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('ALIGN', (1, 0), (1, 0), 'CENTER'),
                    ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
                    ('SPAN', (0, 1), (2, 1)),
                ]))
                story.append(vend_header)
                story.append(Spacer(1, 1.3 * mm))

                data = [[
                    _p('Tipo', styles['table_head']),
                    _p('Campanha / item', styles['table_head']),
                    _p('Qtd / base', styles['table_head']),
                    _p('Vendeu (R$)', styles['table_head']),
                    _p('Valor (R$)', styles['table_head']),
                    _p('Status', styles['table_head']),
                ]]

                line_index = 0
                for camp in (row.get('campanhas') or []):
                    items = camp.get('itens') if isinstance(camp, dict) else None
                    label = str(camp.get('tipo_label') or camp.get('tipo_short') or camp.get('tipo') or '—')
                    title = str(camp.get('titulo') or '—')
                    qtd_txt = _fmt_num(camp.get('qtd_vendida') or 0)
                    vendeu_txt = _fmt_money(camp.get('vendeu_rs') or 0)
                    valor_txt = _fmt_money(camp.get('valor') or 0)
                    st_txt = str(camp.get('status') or 'PENDENTE').replace('_', ' ')
                    st_color = _status_color(st_txt)

                    data.append([
                        _p(escape(label), styles['table_cell_bold']),
                        _p(escape(title), styles['table_cell_bold']),
                        _p(escape(qtd_txt), styles['table_cell_right']),
                        _p(escape(vendeu_txt), styles['table_cell_right']),
                        _p(escape(valor_txt), styles['table_cell_right']),
                        _p(f'<font color="#{st_color.hexval()[2:]}">{escape(st_txt)}</font>', styles['table_cell_bold']),
                    ])
                    line_index += 1

                    for item in (items or []):
                        item_title = f"- {str(item.get('titulo') or 'Item do combo')}"
                        item_qtd = _fmt_num(item.get('qtd_vendida') or 0)
                        item_vendeu = _fmt_money(item.get('vendeu_rs') or 0)
                        item_valor = _fmt_money(item.get('valor') or 0)
                        item_st = str(item.get('status') or camp.get('status') or 'PENDENTE').replace('_', ' ')
                        item_color = _status_color(item_st)
                        data.append([
                            _p('ITEM', styles['table_cell']),
                            _p(escape(item_title), styles['table_cell']),
                            _p(escape(item_qtd), styles['table_cell_right']),
                            _p(escape(item_vendeu), styles['table_cell_right']),
                            _p(escape(item_valor), styles['table_cell_right']),
                            _p(f'<font color="#{item_color.hexval()[2:]}">{escape(item_st)}</font>', styles['table_cell']),
                        ])
                        line_index += 1

                table = Table(
                    data,
                    colWidths=[22 * mm, 113 * mm, 22 * mm, 34 * mm, 34 * mm, 28 * mm],
                    repeatRows=1,
                    splitByRow=1,
                )
                ts = [
                    ('BACKGROUND', (0, 0), (-1, 0), PDF_BG),
                    ('BOX', (0, 0), (-1, -1), 0.5, PDF_GRID),
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
                    bg = PDF_PANEL if ridx % 2 else PDF_PANEL_2
                    ts.append(('BACKGROUND', (0, ridx), (-1, ridx), bg))
                table.setStyle(TableStyle(ts))
                story.append(table)
                story.append(Spacer(1, 3.2 * mm))

            if idx != len(emp_cards) - 1:
                story.append(Spacer(1, 3 * mm))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
