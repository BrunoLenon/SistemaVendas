from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


PDF_TEXT = colors.HexColor('#1f2937')
PDF_MUTED = colors.HexColor('#64748b')
PDF_PRIMARY = colors.HexColor('#2563eb')
PDF_PRIMARY_DARK = colors.HexColor('#1d4ed8')
PDF_PRIMARY_SOFT = colors.HexColor('#eff6ff')
PDF_ORANGE = colors.HexColor('#f97316')
PDF_ORANGE_SOFT = colors.HexColor('#fff7ed')
PDF_HEADER = colors.HexColor('#f8fafc')
PDF_BORDER = colors.HexColor('#cbd5e1')
PDF_GRID = colors.HexColor('#e2e8f0')
PDF_ROW_ALT = colors.HexColor('#f8fafc')
PDF_WHITE = colors.white
PDF_GREEN = colors.HexColor('#15803d')
PDF_YELLOW = colors.HexColor('#b45309')
PDF_RED = colors.HexColor('#b91c1c')

PAGE_WIDTH, PAGE_HEIGHT = A4
PAGE_MARGIN_X = 8 * mm
PAGE_MARGIN_TOP = 8 * mm
PAGE_MARGIN_BOTTOM = 12 * mm
CONTENT_WIDTH = PAGE_WIDTH - (PAGE_MARGIN_X * 2)


# Largura total: 194mm em A4 vertical com margem de 8mm.
TABLE_COL_WIDTHS = [18 * mm, 79 * mm, 20 * mm, 28 * mm, 29 * mm, 20 * mm]


def _fmt_money(v: object) -> str:
    try:
        num = float(v or 0)
    except Exception:
        num = 0.0
    s = f'{num:,.2f}'.replace(',', 'X').replace('.', ',').replace('X', '.')
    return f'R$ {s}'


def _fmt_num(v: object) -> str:
    try:
        num = float(v or 0)
    except Exception:
        return '0'
    if abs(num - round(num)) < 0.000001:
        return f'{int(round(num))}'
    return f'{num:,.2f}'.replace(',', 'X').replace('.', ',').replace('X', '.')


def _fmt_pct(v: object) -> str:
    try:
        return f"{float(v or 0):,.2f}%".replace(',', 'X').replace('.', ',').replace('X', '.')
    except Exception:
        return '0,00%'


def _status_text(status: str) -> str:
    return str(status or 'PENDENTE').strip().upper().replace('_', ' ')


def _status_color(status: str):
    st = _status_text(status)
    if st == 'PAGO':
        return PDF_GREEN
    if st == 'A PAGAR':
        return PDF_YELLOW
    return PDF_RED


def _hex(color) -> str:
    try:
        return f"#{color.hexval()[2:]}"
    except Exception:
        return '#1f2937'


def _safe_text(value: object, default: str = '—') -> str:
    text = str(value if value is not None else '').strip()
    return text or default


def _build_styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle(
            'ExportTitle', parent=base['Heading1'], fontName='Helvetica-Bold',
            fontSize=15.5, leading=17.5, textColor=PDF_TEXT, alignment=TA_LEFT,
            spaceAfter=0,
        ),
        'subtitle': ParagraphStyle(
            'ExportSubtitle', parent=base['BodyText'], fontName='Helvetica',
            fontSize=7.2, leading=8.6, textColor=PDF_MUTED, alignment=TA_RIGHT,
        ),
        'kpi_label': ParagraphStyle(
            'KpiLabel', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=6.3, leading=7.4, textColor=PDF_MUTED, alignment=TA_LEFT,
        ),
        'kpi_value': ParagraphStyle(
            'KpiValue', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=9.4, leading=10.7, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'emp_title': ParagraphStyle(
            'EmpTitle', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=9.2, leading=10.4, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'emp_meta': ParagraphStyle(
            'EmpMeta', parent=base['BodyText'], fontName='Helvetica',
            fontSize=6.7, leading=7.8, textColor=PDF_MUTED, alignment=TA_RIGHT,
        ),
        'seller': ParagraphStyle(
            'Seller', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=7.5, leading=8.6, textColor=PDF_TEXT, alignment=TA_LEFT,
        ),
        'seller_right': ParagraphStyle(
            'SellerRight', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=7.5, leading=8.6, textColor=PDF_TEXT, alignment=TA_RIGHT,
        ),
        'head': ParagraphStyle(
            'TableHead', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=6.3, leading=7.2, textColor=PDF_TEXT, alignment=TA_CENTER,
        ),
        'cell': ParagraphStyle(
            'TableCell', parent=base['BodyText'], fontName='Helvetica',
            fontSize=6.4, leading=7.4, textColor=PDF_TEXT, alignment=TA_LEFT,
            splitLongWords=True,
        ),
        'cell_bold': ParagraphStyle(
            'TableCellBold', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=6.4, leading=7.4, textColor=PDF_TEXT, alignment=TA_LEFT,
            splitLongWords=True,
        ),
        'cell_right': ParagraphStyle(
            'TableCellRight', parent=base['BodyText'], fontName='Helvetica',
            fontSize=6.4, leading=7.4, textColor=PDF_TEXT, alignment=TA_RIGHT,
        ),
        'cell_right_bold': ParagraphStyle(
            'TableCellRightBold', parent=base['BodyText'], fontName='Helvetica-Bold',
            fontSize=6.4, leading=7.4, textColor=PDF_TEXT, alignment=TA_RIGHT,
        ),
        'cell_center': ParagraphStyle(
            'TableCellCenter', parent=base['BodyText'], fontName='Helvetica',
            fontSize=6.4, leading=7.4, textColor=PDF_TEXT, alignment=TA_CENTER,
        ),
        'footer': ParagraphStyle(
            'Footer', parent=base['BodyText'], fontName='Helvetica',
            fontSize=6.7, leading=7.8, textColor=PDF_MUTED, alignment=TA_RIGHT,
        ),
    }


def _p(text: object, style) -> Paragraph:
    return Paragraph(str(text or ''), style)


def _metric_cell(label: str, value: object, styles):
    return [_p(escape(label), styles['kpi_label']), _p(escape(_fmt_money(value)), styles['kpi_value'])]


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(PDF_GRID)
    canvas.setLineWidth(0.4)
    canvas.line(doc.leftMargin, PAGE_MARGIN_BOTTOM - 2.5 * mm, PAGE_WIDTH - doc.rightMargin, PAGE_MARGIN_BOTTOM - 2.5 * mm)
    canvas.setFillColor(PDF_MUTED)
    canvas.setFont('Helvetica', 6.8)
    canvas.drawString(doc.leftMargin, 5.8 * mm, 'Veipeças • Relatório de Campanhas')
    canvas.drawRightString(PAGE_WIDTH - doc.rightMargin, 5.8 * mm, f'Página {canvas.getPageNumber()}')
    canvas.restoreState()


def _tipo_chip_text(tipos_resumo: list[dict] | None) -> str:
    tipos_resumo = tipos_resumo or []
    if not tipos_resumo:
        return 'Sem tipos destacados'
    return ' • '.join(
        f"{str(t.get('short') or t.get('label') or '').upper()} ({int(t.get('count') or 0)})"
        for t in tipos_resumo
    )


def _build_header(*, ano: int, mes: int, emps_sel: list[str], resumo: dict, styles):
    emps = ', '.join([str(e) for e in (emps_sel or [])]) if emps_sel else 'todas as selecionadas'
    subtitle = (
        f'<b>Competência:</b> {mes:02d}/{ano}<br/>'
        f'<b>EMPs:</b> {escape(emps)}<br/>'
        'Impressão vertical compacta'
    )
    header = Table(
        [[_p(f'Relatório de Campanhas {mes:02d}/{ano}', styles['title']), _p(subtitle, styles['subtitle'])]],
        colWidths=[108 * mm, CONTENT_WIDTH - (108 * mm)],
    )
    header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_WHITE),
        ('BOX', (0, 0), (-1, -1), 0.55, PDF_BORDER),
        ('LINEBELOW', (0, 0), (-1, -1), 1.0, PDF_PRIMARY),
        ('LEFTPADDING', (0, 0), (-1, -1), 7),
        ('RIGHTPADDING', (0, 0), (-1, -1), 7),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    status = (resumo or {}).get('status', {}) if isinstance(resumo, dict) else {}
    metric_data = [[
        _metric_cell('Total geral', (resumo or {}).get('total_valor', 0), styles),
        _metric_cell('Pendente', status.get('PENDENTE', 0), styles),
        _metric_cell('A pagar', status.get('A_PAGAR', 0), styles),
        _metric_cell('Pago', status.get('PAGO', 0), styles),
    ]]
    metric_table = Table(metric_data, colWidths=[CONTENT_WIDTH / 4] * 4)
    metric_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_HEADER),
        ('BOX', (0, 0), (-1, -1), 0.45, PDF_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.35, PDF_GRID),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return [header, Spacer(1, 2 * mm), metric_table, Spacer(1, 3 * mm)]


def _build_emp_header(card: dict, styles):
    status_label = _status_text(card.get('status') or 'PENDENTE')
    status_color = _hex(_status_color(status_label))
    left = f"Loja {escape(_safe_text(card.get('emp')))}"
    right = (
        f"<b>Premiação:</b> {_fmt_money(card.get('total', 0))} &nbsp;|&nbsp; "
        f"<b>Vendedores:</b> {int(card.get('vendedores_count') or 0)} &nbsp;|&nbsp; "
        f"<b>Campanhas:</b> {int(card.get('campanhas_count') or 0)} &nbsp;|&nbsp; "
        f"<font color='{status_color}'><b>{escape(status_label)}</b></font>"
    )
    fat_line = (
        f"<b>Venda balcão:</b> {_fmt_money(card.get('faturamento_balcao', 0))} &nbsp;|&nbsp; "
        f"<b>Venda oficina:</b> {_fmt_money(card.get('faturamento_oficina', 0))} &nbsp;|&nbsp; "
        f"<b>Faturamento total:</b> {_fmt_money(card.get('faturamento_total', 0))}"
    )
    emp_header = Table(
        [[_p(left, styles['emp_title']), _p(right, styles['emp_meta'])],
         [_p(fat_line, styles['cell']), ''],
         [_p(escape(_tipo_chip_text(card.get('tipos_resumo') or [])), styles['cell']), '']],
        colWidths=[72 * mm, CONTENT_WIDTH - (72 * mm)],
    )
    emp_header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PDF_PRIMARY_SOFT),
        ('BOX', (0, 0), (-1, -1), 0.55, PDF_BORDER),
        ('LINEBELOW', (0, 0), (-1, 0), 0.35, PDF_GRID),
        ('LINEBELOW', (0, 1), (-1, 1), 0.25, PDF_GRID),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('SPAN', (0, 1), (1, 1)),
        ('SPAN', (0, 2), (1, 2)),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return emp_header


def _make_status_paragraph(status: str, style):
    st_txt = _status_text(status)
    return _p(f"<font color='{_hex(_status_color(st_txt))}'><b>{escape(st_txt)}</b></font>", style)


def _campaign_title(camp: dict, *, prefix: str = '') -> str:
    title = _safe_text(camp.get('titulo'))
    code = _safe_text(camp.get('item_codigo'), default='')
    desc = _safe_text(camp.get('item_descricao'), default='')
    marca = _safe_text(camp.get('item_marca') or camp.get('marca'), default='')

    criterios = []
    if desc and desc != '—':
        criterios.append(f'Desc.: {desc}')
    elif code and code != '—':
        criterios.append(f'Cód.: {code}')
    if marca and marca != '—':
        criterios.append(f'Marca: {marca}')
    if criterios:
        title = f"{title} | {' • '.join(criterios)}"

    if str(camp.get('tipo_key') or '').upper() == 'META':
        reqs = []
        if camp.get('faturamento_minimo_meta'):
            if camp.get('bloqueado_minimo'):
                reqs.append(f"fat. mínimo pendente ({_fmt_money(camp.get('faturamento_minimo_meta'))})")
            else:
                reqs.append('fat. mínimo OK')
        if camp.get('margem_minima'):
            atual = 'sem margem' if camp.get('margem_percentual') is None else _fmt_pct(camp.get('margem_percentual'))
            minimo = _fmt_pct(camp.get('margem_minima'))
            if camp.get('bloqueado_margem'):
                reqs.append(f"margem abaixo ({atual} / mín. {minimo})")
            else:
                reqs.append(f"margem OK ({atual} / mín. {minimo})")
        if reqs:
            title = f"{title} | {'; '.join(reqs)}"

    return f'{prefix}{title}'


def _append_campaign_row(data: list, styles, camp: dict, *, is_item: bool = False):
    label = 'ITEM' if is_item else str(camp.get('tipo_short') or camp.get('tipo_label') or camp.get('tipo') or '—').upper()
    title = _campaign_title(camp, prefix='• ' if is_item else '')
    qtd_txt = _fmt_num(camp.get('qtd_vendida') or 0)
    vendeu_txt = _fmt_money(camp.get('vendeu_rs') or 0)
    valor_txt = _fmt_money(camp.get('valor') or 0)
    st_txt = _status_text(camp.get('status') or 'PENDENTE')
    title_style = styles['cell'] if is_item else styles['cell_bold']
    data.append([
        _p(escape(label), styles['cell_center']),
        _p(escape(title), title_style),
        _p(escape(qtd_txt), styles['cell_right']),
        _p(escape(vendeu_txt), styles['cell_right']),
        _p(escape(valor_txt), styles['cell_right_bold']),
        _make_status_paragraph(st_txt, styles['cell_center']),
    ])


def _build_campaigns_table(card: dict, styles):
    data = [[
        _p('Tipo', styles['head']),
        _p('Campanha / item', styles['head']),
        _p('Qtd', styles['head']),
        _p('Vendeu', styles['head']),
        _p('Valor', styles['head']),
        _p('Status', styles['head']),
    ]]
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), PDF_HEADER),
        ('TEXTCOLOR', (0, 0), (-1, 0), PDF_TEXT),
        ('BOX', (0, 0), (-1, -1), 0.45, PDF_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.25, PDF_GRID),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 3.2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3.2),
        ('TOPPADDING', (0, 0), (-1, -1), 2.4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.4),
        ('ALIGN', (2, 1), (4, -1), 'RIGHT'),
        ('ALIGN', (0, 1), (0, -1), 'CENTER'),
        ('ALIGN', (5, 1), (5, -1), 'CENTER'),
    ]

    row_idx = 1
    for row in (card.get('rows') or []):
        vend_status = _status_text(row.get('status') or 'PENDENTE')
        seller_left = (
            f"<b>Vendedor:</b> {escape(_safe_text(row.get('vendedor')))}"
            f" &nbsp;&nbsp; <font color='{_hex(PDF_MUTED)}'>Campanhas: {int(row.get('campanhas_count') or 0)}</font>"
        )
        seller_right = (
            f"<b>Total a receber:</b> {_fmt_money(row.get('total', 0))}"
            f" &nbsp;&nbsp; <font color='{_hex(_status_color(vend_status))}'><b>{escape(vend_status)}</b></font>"
        )
        data.append([
            _p(seller_left, styles['seller']), '', '',
            _p(seller_right, styles['seller_right']), '', '',
        ])
        style_cmds.extend([
            ('BACKGROUND', (0, row_idx), (-1, row_idx), PDF_ORANGE_SOFT),
            ('SPAN', (0, row_idx), (2, row_idx)),
            ('SPAN', (3, row_idx), (5, row_idx)),
            ('LINEABOVE', (0, row_idx), (-1, row_idx), 0.5, PDF_ORANGE),
            ('TOPPADDING', (0, row_idx), (-1, row_idx), 3.2),
            ('BOTTOMPADDING', (0, row_idx), (-1, row_idx), 3.2),
        ])
        row_idx += 1

        campanhas = row.get('campanhas') or []
        if not campanhas:
            data.append(['', _p('Sem campanhas detalhadas para este vendedor.', styles['cell']), '', '', '', ''])
            style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), PDF_WHITE))
            row_idx += 1
            continue

        for camp in campanhas:
            _append_campaign_row(data, styles, camp, is_item=False)
            style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), PDF_WHITE if row_idx % 2 else PDF_ROW_ALT))
            row_idx += 1
            for item in (camp.get('itens') or []):
                item = {**item, 'status': item.get('status') or camp.get('status')}
                _append_campaign_row(data, styles, item, is_item=True)
                style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), PDF_WHITE if row_idx % 2 else PDF_ROW_ALT))
                row_idx += 1

    table = Table(
        data,
        colWidths=TABLE_COL_WIDTHS,
        repeatRows=1,
        splitByRow=1,
    )
    table.setStyle(TableStyle(style_cmds))
    return table


def build_relatorio_campanhas_pdf(
    *,
    ano: int,
    mes: int,
    emps_sel: list[str],
    resumo: dict,
    emp_cards: list[dict],
) -> bytes:
    """Gera PDF do relatório de campanhas em A4 vertical e formato compacto.

    A estrutura foi pensada para impressão: um cabeçalho curto, KPIs em linha e,
    abaixo, blocos por loja com vendedores e campanhas dentro de uma única tabela.
    Isso reduz espaçamentos extras e evita o layout horizontal antigo.
    """
    styles = _build_styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=PAGE_MARGIN_X,
        rightMargin=PAGE_MARGIN_X,
        topMargin=PAGE_MARGIN_TOP,
        bottomMargin=PAGE_MARGIN_BOTTOM,
        title=f'Relatório de Campanhas {mes:02d}/{ano}',
        author='Veipeças',
    )

    story = []
    story.extend(_build_header(ano=ano, mes=mes, emps_sel=emps_sel, resumo=resumo or {}, styles=styles))

    if not emp_cards:
        empty = Table(
            [[_p('Nenhum dado encontrado para os filtros selecionados.', styles['emp_title'])]],
            colWidths=[CONTENT_WIDTH],
        )
        empty.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), PDF_WHITE),
            ('BOX', (0, 0), (-1, -1), 0.55, PDF_BORDER),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(empty)
    else:
        for emp_idx, card in enumerate(emp_cards):
            if emp_idx:
                story.append(Spacer(1, 2.5 * mm))
            story.append(_build_emp_header(card, styles))
            story.append(_build_campaigns_table(card, styles))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
