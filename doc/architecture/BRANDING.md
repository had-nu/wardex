# Wardex Brand System

## Posicionamento

O Wardex transforma decisões de segurança e conformidade em evidência auditável.

- **Promessa principal (PT):** Decisões de segurança e conformidade auditáveis.
- **Primary promise (EN):** Auditable security and compliance decisions.
- **Descriptor secundário:** Risk-based release governance.

O release gate é uma capacidade central do produto; a identidade não deve excluir a análise de conformidade, auditoria, proveniência e os restantes comandos da CLI.

## Símbolo Shield

O símbolo aprovado é um **shield/armamento simétrico**:

- a lâmina central representa a decisão e a autoridade;
- os dois braços representam protecção, policy e o caminho de evidência;
- o corte central sugere uma decisão verificável, não apenas um monitor;
- o quadrado e a geometria fechada comunicam integridade e confiança;
- o símbolo é produzido sozinho, sem lettering, num asset quadrado com fundo transparente.

A referência visual fornecida está em `doc/internal/assets/shield-w.jpg`. O asset de produção `pkg/ui/wardex-shield.png` é um recorte quadrado, transparente e recolorido na cor do Wardex. `pkg/ui/wardex-shield-dark.png` é a variante para fundos escuros.

Não reintroduzir o símbolo radar/scanner, o W de traço contínuo ou construções experimentais anteriores.

## Sistema visual

| Papel | Light | Dark | Uso |
|---|---|---|---|
| Brand | `#6F42C1` | `#A78BFA` | shield, wordmark e destaque de marca |
| Structure | `#2AB5DC` | `#2AB5DC` | estrutura da UI; não compete com o shield |
| Background | `#FFFFFF` | `#0D1117` | superfícies documentais |
| Text | `#111827` | `#F0F6FC` | texto principal |
| Muted text | `#374151` | `#8B949E` | metadata secundária |
| Success | `#42E5A1` | `#42E5A1` | estado positivo; nunca brand |
| Warning | `#F2D34D` | `#F2D34D` | estado de atenção; nunca brand |
| Danger | `#F04F6D` | `#F04F6D` | bloqueio/erro; nunca brand |

O roxo é a cor de assinatura. Ciano, verde, âmbar e vermelho têm função semântica. O antigo teal `#00C4A7` pode continuar a representar sucesso/cobertura em relatórios, mas não deve ser usado como cor primária da marca.

## Assets e variantes

- `pkg/ui/wardex-shield.png` — símbolo light, quadrado e transparente.
- `pkg/ui/wardex-shield-dark.png` — símbolo dark, quadrado e transparente.
- `pkg/ui/wardex-lockup.svg` — wrapper SVG do símbolo, sem lettering.
- `pkg/ui/wardex-lockup-dark.svg` — wrapper SVG dark, sem lettering.
- `pkg/ui/wardex-icon.svg` — ícone principal.
- `pkg/ui/wardex-icon-dark.svg` — ícone para fundos escuros.
- `pkg/ui/wardex-icon-stroke.svg` — nome legado, mantido para compatibilidade.
- `pkg/ui/wardex-icon-teal.svg` — nome legado, mantido para compatibilidade.
- `docs/assets/og-image.svg` — fonte do Open Graph image.
- `docs/assets/favicon.svg` — ícone da página GitHub Pages.
- `doc/internal/assets/banner.svg` — fonte do banner de release.

Os SVGs de lockup são wrappers do PNG e não contêm lettering. O README compõe `WARDEX` e o descriptor como HTML. Os PNGs de saída são gerados a partir dos SVG:

```bash
rsvg-convert -w 1200 -h 630 docs/assets/og-image.svg -o docs/assets/og-image.png
rsvg-convert -w 840 -h 228 doc/internal/assets/banner.svg -o doc/internal/assets/banner.png
```

Os SVGs devem manter `title`, `desc`, `role="img"` e `aria-labelledby`. No README, usar `<picture>` para seleccionar a variante dark com `prefers-color-scheme`.

## Regras de uso

- Não reintroduzir o símbolo radar/scanner anterior.
- Não usar neon magenta/ciano como linguagem principal da marca.
- Não usar escudo, cadeado ou checkmark literais diferentes do shield aprovado.
- Não adicionar lettering, pontos ou outros elementos dentro do PNG do símbolo.
- Não depender apenas de cor para comunicar estados.
- O header da CLI pode manter um marcador compacto separado; o shield completo pertence aos assets documentais.
- Em pipes, CI, JSON, CSV e relatórios machine-oriented, a marca deve permanecer ausente ou ser explicitamente opcional.
- O banner e o Open Graph image devem seguir a mesma promessa, paleta e descriptor do README.

## Checklist de consistência

Antes de publicar uma superfície nova, confirmar:

- [ ] A promessa principal é a mesma em PT e EN.
- [ ] O shield aparece sozinho, quadrado e transparente.
- [ ] Não há lettering nem pontos dentro do asset do símbolo.
- [ ] O roxo é usado como marca, não como estado semântico.
- [ ] O contraste do texto e do símbolo foi verificado.
- [ ] Existe comportamento light/dark ou fallback monocromático.
- [ ] O asset tem descrição acessível e não contém segredos.
