# Wardex Exit Codes

O Wardex segue uma convenção estrita de Exit Codes para permitir fácil integração e orquestração em ferramentas de CI/CD, scripts bash, e pipelines automatizadas. Para garantir previsibilidade e evitar colisões com *shell built-ins* POSIX (como o `exit 2`), o Wardex implementa constantes de erro semâmicas.

## Tabela de Exit Codes

| Exit Code | Categoria | Descrição / Motivo | Ação Recomendada |
| :---: | :--- | :--- | :--- |
| **`0`** | **Sucesso** | Operação concluída com êxito. O Release Gate aprovou todas as vulnerabilidades face ao contexto / apetite de risco estabelecido. | Continuar a pipeline (Deploy). |
| **`1`** | **Erro Execução** | Erro genérico de execução: má formatação de ficheiros YAML/JSON, falta de permissões de leitura, sintaxe de CLI incorreta, ou path não encontrado. | Corrigir a sintaxe, sintaxe de YAML, ou paths. |
| **`3`** | **Integridade** | **Tampered**: Configuração ou aceitação de risco falhou a validação de assinatura HMAC-SHA256 (adulteração maliciosa, selo `.wexstate` não corresponde, ou config hash drift). | Reverter as alterações. Correr `wardex config seal` novamente ou `wardex accept verify`. |
| **`4`** | **Integridade** | **Store Inconsistent**: Discrepância detetada entre o número de aceitações no ficheiro e o log de auditoria append-only (`wardex-accept-audit.log`). | Investigar deleções manuais arbitrárias no log. |
| **`5`** | **Operacional** | **Expiring Soon**: O comando `policy check-expiry` detetou aceitações que vão expirar dentro da janela de aviso. | Renovar as aceitações ou corrigir vulnerabilidades. |
| **`10`** | **Políticas** | **Gate Blocked**: Pelo menos uma vulnerabilidade excede o risco tolerável face aos controlos + apetite ao risco. | Analisar e corrigir ou invocar `wardex accept request`. |
| **`11`** | **Políticas** | **Compliance Fail**: Rácio de cobertura/maturidade abaixo do exigido pelo `--fail-above`. | Rever controlos implementados e documentados. |
| **`12`** | **CRA** | **Active Exploitation**: Vulnerabilidade no catálogo CISA KEV. Requer notificação Article 14. | Executar `wardex art14 show` para inspeccionar o artefacto gerado. Não pode ser substituído por aceitação de risco. |

### Uso em Pipelines CI/CD

Exemplo de interpretação do output do processo principal numa pipeline:

```bash
wardex evaluate --evidence vulns.yaml --config wardex-config.yaml
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "[PASS] Release Gate Aprovado." ;;
  10)
    echo "[BLOCK] Release Bloqueada (Gate). Solicite Risk Acceptance."
    exit 1 ;;
  11)
    echo "[WARN] Compliance Ratio Insuficiente. Reveja controlos."
    exit 1 ;;
  12)
    echo "[CRA] Active Exploitation — notificação Article 14 necessária."
    exit 1 ;;
  3)
    echo "[FAIL] Integridade: configuração adulterada."
    exit 1 ;;
  *)
    echo "[FAIL] Erro Fatal (Code: $EXIT_CODE)."
    exit 1 ;;
esac
```

---

## CPL — Configuration Provenance Link (v2.2+)

Os comandos `wardex audit verify-link` e `wardex audit verify-chain` produzem exit codes
específicos para integração em pipelines e notificações:

| Código | Condição |
|--------|----------|
| 0 | Todas as entradas com estado `OK` |
| 1 | Uma ou mais entradas com `MISMATCH` ou `MISSING` |
| 2 | Erro operacional (ficheiro inacessível, parse error) |
