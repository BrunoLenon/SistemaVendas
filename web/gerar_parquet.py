import pandas as pd

CAMINHO_PLANILHA = r"C:\Users\lenon\Documents\SistemaVendas\planilha\vendas.xlsx"
CAMINHO_PARQUET  = r"C:\Users\lenon\Documents\SistemaVendas\planilha\vendas.parquet"

df = pd.read_excel(CAMINHO_PLANILHA)

# Forçar colunas que podem ter letras/números para TEXTO
colunas_texto = ["MESTRE", "MARCA", "VENDEDOR", "NOTA", "EMP", "MOV_TIPO_MOVTO"]
for col in colunas_texto:
    if col in df.columns:
        df[col] = df[col].astype(str).str.strip()

# Garantir tipos úteis
if "MOVIMENTO" in df.columns:
    df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")

if "VALOR_TOTAL" in df.columns:
    df["VALOR_TOTAL"] = pd.to_numeric(df["VALOR_TOTAL"], errors="coerce").fillna(0)

df.to_parquet(CAMINHO_PARQUET, index=False)

print("OK! Parquet criado em:", CAMINHO_PARQUET)
print("Linhas:", len(df))
print("Colunas:", list(df.columns))
