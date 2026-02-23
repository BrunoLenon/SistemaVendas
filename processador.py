import pandas as pd
from datetime import datetime

# =========================
# CONFIGURAÇÕES
# =========================
CAMINHO_PLANILHA = r"C:\Users\lenon\Documents\SistemaVendas\planilha\vendas.xlsx"
VENDEDOR_ANALISE = "RAFAEL"  # depois isso virá do login

# =========================
# PERÍODO DE ANÁLISE (CONFIGURÁVEL)
# =========================
# Ex.: Janeiro/2026 => ano_atual=2026, mes_atual=1
ano_atual = 2025
mes_atual = 12

# =========================
# LEITURA DOS DADOS
# =========================
df = pd.read_excel(CAMINHO_PLANILHA)

# Garantir tipos corretos
df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
df["VALOR_TOTAL"] = pd.to_numeric(df["VALOR_TOTAL"], errors="coerce").fillna(0)

# =========================
# MOVIMENTOS NEGATIVOS (DS/CA)
# =========================
# Regra: se MOV_TIPO_MOVTO for "DS" ou "CA", o valor deve entrar como negativo.
if "MOV_TIPO_MOVTO" not in df.columns:
    df["MOV_TIPO_MOVTO"] = ""

df["MOV_TIPO_MOVTO"] = df["MOV_TIPO_MOVTO"].astype(str).str.strip().str.upper()

eh_negativo = df["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
df["VALOR_ASSINADO"] = df["VALOR_TOTAL"].where(~eh_negativo, -df["VALOR_TOTAL"])

# =========================
# FILTRO POR VENDEDOR
# =========================
df_vend = df[df["VENDEDOR"] == VENDEDOR_ANALISE].copy()

if df_vend.empty:
    print("❌ Nenhum dado encontrado para o vendedor:", VENDEDOR_ANALISE)
    raise SystemExit(1)

# =========================
# FILTRO POR PERÍODO
# =========================
df_mes_atual = df_vend[
    (df_vend["MOVIMENTO"].dt.year == ano_atual) &
    (df_vend["MOVIMENTO"].dt.month == mes_atual)
].copy()

# =========================
# 1️⃣ MIX DE PRODUTOS (somente movimentos positivos)
# =========================
df_mes_atual_vendas = df_mes_atual[~df_mes_atual["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
mix_atual = df_mes_atual_vendas["MESTRE"].nunique()

# =========================
# 2️⃣ VALOR TOTAL (considera DS/CA como negativo)
# =========================
valor_total_atual = df_mes_atual["VALOR_ASSINADO"].sum()

# =========================
# 3️⃣ VALOR POR MARCA (considera DS/CA como negativo)
# =========================
valor_por_marca = (
    df_mes_atual
    .groupby("MARCA")["VALOR_ASSINADO"]
    .sum()
    .sort_values(ascending=False)
)

top10_marcas = valor_por_marca.head(10)

# =========================
# 4️⃣ PERCENTUAL POR MARCA
# =========================
if valor_total_atual != 0:
    percentual_por_marca = (valor_por_marca / valor_total_atual) * 100
    top15_percentual = percentual_por_marca.head(15)
else:
    percentual_por_marca = None
    top15_percentual = None

# =========================
# 5️⃣ CRESCIMENTO vs MÊS ANTERIOR (em VALOR_ASSINADO)
# =========================
if mes_atual == 1:
    mes_ant = 12
    ano_ant = ano_atual - 1
else:
    mes_ant = mes_atual - 1
    ano_ant = ano_atual

df_mes_anterior = df_vend[
    (df_vend["MOVIMENTO"].dt.year == ano_ant) &
    (df_vend["MOVIMENTO"].dt.month == mes_ant)
].copy()

valor_mes_anterior = df_mes_anterior["VALOR_ASSINADO"].sum()

# Obs.: se o mês anterior for 0, não há base de comparação.
# Se for negativo (muito raro, mas possível com muitas devoluções), usamos abs() no denominador para não inverter o sentido.
if valor_mes_anterior != 0:
    crescimento = ((valor_total_atual - valor_mes_anterior) / abs(valor_mes_anterior)) * 100
else:
    crescimento = None

# =========================
# 6️⃣ COMPARAÇÃO COM MESMO MÊS DO ANO PASSADO
# =========================
ano_passado = ano_atual - 1

df_mes_ano_passado = df_vend[
    (df_vend["MOVIMENTO"].dt.year == ano_passado) &
    (df_vend["MOVIMENTO"].dt.month == mes_atual)
].copy()

valor_ano_passado = df_mes_ano_passado["VALOR_ASSINADO"].sum()

df_mes_ano_passado_vendas = df_mes_ano_passado[~df_mes_ano_passado["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
mix_ano_passado = df_mes_ano_passado_vendas["MESTRE"].nunique()

# =========================
# 📊 RESULTADOS
# =========================
print("\n==============================")
print("📊 RESUMO DO VENDEDOR:", VENDEDOR_ANALISE)
print("==============================")

print(f"\n🔹 MIX DE PRODUTOS (mês atual): {mix_atual}")
print(f"🔸 MIX ano passado (mesmo mês): {mix_ano_passado}")

print(f"\n💰 VALOR TOTAL (mês atual): R$ {valor_total_atual:,.2f}")
print(f"💰 VALOR ano passado (mesmo mês): R$ {valor_ano_passado:,.2f}")

print("\n📈 CRESCIMENTO vs mês anterior:")
if crescimento is None:
    print("   Mês anterior sem base para comparação.")
else:
    print(f"   {crescimento:.2f}%")

print("\n🏷️ TOP 10 MARCAS POR VALOR:")
for marca, valor in top10_marcas.items():
    print(f"   {marca}: R$ {valor:,.2f}")

print("\n📊 TOP 15 MARCAS POR PERCENTUAL:")
if top15_percentual is None:
    print("   Sem percentuais (total do mês = 0).")
else:
    for marca, pct in top15_percentual.items():
        print(f"   {marca}: {pct:.2f}%")
