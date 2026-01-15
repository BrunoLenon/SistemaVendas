import pandas as pd
from datetime import datetime
import shutil
import os

# Caminhos
BASE_DIR = r"C:\Users\lenon\Documents\SistemaVendas"
PLANILHA = os.path.join(BASE_DIR, "planilha", "vendas.xlsx")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")

def criar_backup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    hoje = datetime.now().strftime("%Y-%m-%d_%H-%M")
    nome_backup = f"vendas_backup_{hoje}.xlsx"
    destino = os.path.join(BACKUP_DIR, nome_backup)

    shutil.copy2(PLANILHA, destino)
    print(f"✅ Backup criado: {destino}")

def ler_planilha():
    df = pd.read_excel(PLANILHA)

    print("\n📊 RESUMO DOS DADOS")
    print(f"Total de registros: {len(df)}")

    print("\nColunas encontradas:")
    print(list(df.columns))

    # Conferência básica
    colunas_esperadas = [
        "MESTRE", "MARCA", "MOVIMENTO", "INTERNO", "VENDEDOR",
        "NOTA", "EMP", "UNIT", "DES", "QTDADE_VENDIDA", "VALOR_TOTAL"
    ]

    faltando = [c for c in colunas_esperadas if c not in df.columns]

    if faltando:
        print("\n⚠️ ATENÇÃO: Estão faltando colunas:")
        for c in faltando:
            print(" -", c)
    else:
        print("\n✅ Todas as colunas estão corretas.")

    return df

if __name__ == "__main__":
    print("🔄 Iniciando sincronizador...\n")
    criar_backup()
    df = ler_planilha()
    print("\n🎉 Processo finalizado com sucesso.")
