PATCH - Passo 1 (Recomendado): Blindagem de Permissões

O que muda:
- Adiciona o decorator `roles_required()` em `web/authz.py`, além de atalhos:
  - supervisor_required, vendedor_required, financeiro_required

Por quê:
- Evita erro em deploy/execução quando alguma rota usa `@roles_required("admin")`
- Padroniza o caminho para permissões e reduz regressões.

Como aplicar:
1) Substitua o arquivo do seu repo:
   SistemaVendas/web/authz.py
   pelo arquivo deste patch.

2) Faça commit e deploy.

Obs:
- Este patch é compatível mesmo que você não esteja usando `roles_required` hoje.
