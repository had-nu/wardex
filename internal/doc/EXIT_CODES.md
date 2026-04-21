# Wardex Exit Codes

O Wardex segue uma convenção estrita de Exit Codes para permitir fácil integração e orquestração em ferramentas de CI/CD, scripts bash, e pipelines automatizadas. Para garantir previsibilidade e evitar colisões com *shell built-ins* POSIX (como o `exit 2`), o Wardex implementa constantes de erro semâmicas (introduzidas no path `v1.1.1`).

## Tabela de Exit Codes

| Exit Code | Categoria | Descrição / Motivo | Ação Recomendada |
| :---: | :--- | :--- | :--- |
| **`0`** | **Sucesso** | Operação concluída com êxito. O Release Gate aprovou todas as vulnerabilidades face ao contexto / apetite de risco estabelecido. | Continuar a pipeline (Deploy). |
| **`1`** | **Erro Execução** | Erro genérico de execução: má formatação de ficheiros YAML/JSON, falta de permissões de leitura, sintaxe de CLI incorreta, ou path não encontrado. | Corrigir a sintaxe, sintaxe de YAML, ou paths. |
| **`3`** | **Integridade** | **Tampered**: Uma aceitação de risco submetida ou ativa falhou a validação de assinatura HMAC-SHA256 (adulteração maliciosa ou corrupção de config hash drift). | Reverter as alterações ao ficheiro de acceptances. Correr `wardex accept verify`. |
| **`4`** | **Integridade** | **Store Inconsistent**: Discrepância detetada entre o número de aceitações no YAML/JSON trace e o número real de ações lidas no log de auditoria append-only (`wardex-accept-audit.log`). | Investigar deleções manuais arbitrárias no log. |
| **`5`** | **Operacional** | **Expiring Soon**: O comando de verificação `check-expiry` detetou acceptances que vão expirar num tempo inferior à janela de aviso de segurança. | Renovar as aceitações (gerar novas) ou corrigir vulnerabilidades na base. |
| **`10`** | **Políticas** | **Gate Blocked**: Pelo menos uma vulnerabilidade lida excede severamente o impacto mitigado pelos controlos da organização + apetite ao risco. Pipeline barrada. | Analisar e corrigir código falho ou invocar o comando `wardex accept request`. |
| **`11`** | **Políticas** | **Compliance Fail**: Falha baseada estritamente num rácio de cobertura/maturidade abaixo do tolerável exigido pelas políticas da organização (`--fail-above`). | Validar os controlos implementados em `dummy_controls.yaml`. |

### Uso em Pipelines CI/CD

Exemplo de interpretação do output do processo principal numa pipeline:

```bash
./bin/wardex --config wardex-config.yaml --gate vulnerabilities.yaml controls.yaml
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "[PASS] Release Gate Aprovado."
elif [ $EXIT_CODE -eq 10 ]; then
  echo "🚫 Release Bloqueada (Gate Fallback). Por favor peça uma Risk Acceptance para as falhas."
  exit 1
elif [ $EXIT_CODE -eq 11 ]; then
  echo "[WARN] Compliance Ratio Insuficiente. Reveja a postura de controlos ISO 27001."
  exit 1
else
  echo "[FAIL] Erro Fatal de Validação / Integridade (Code: $EXIT_CODE)."
  exit 1
fi
```
