---
name: go-security
description: Expert em programação Go idiomática com foco em segurança, sistema design e pensamento adversário. Activar para qualquer código Go no ecosistema do utilizador — CLI tools (Cobra), scanners com file walking, APIs, TUIs (Bubbletea), JSON envelopes entre serviços, ou qualquer revisão/desenho de código Go. Incorpora as Cinco Regras de Rob Pike como foundation, Effective Go, e segurança como cross-cutting concern. Usar mesmo que o pedido não mencione segurança explicitamente — código idiomático e simples é código seguro.
---

# Go Expert — Pike + Segurança

Código Go bem feito e código Go seguro são a mesma coisa. Complexidade é um vetor de ataque: bugs escondem-se na obscuridade. A âncora são as **Cinco Regras de Rob Pike**.

---

## As Cinco Regras de Rob Pike

**Regra 1 — Não advinhas onde o programa vai gastar tempo.**
Bottlenecks aparecem em sítios surpreendentes. Não optimizes até provares onde está o problema. Em segurança: não adds controles preventivos para ameaças que não consegues articular concretamente.

**Regra 2 — Mede. Não optimizes até medires.**
`go test -bench`, `pprof`, `go test -race`. Em segurança: `govulncheck`, `gosec`, `staticcheck` — ferramentas que medem, não intuição.

**Regra 3 — Algoritmos fancy são lentos quando n é pequeno — e n é quase sempre pequeno.**
A bubble sort com n≤93 explicitamente comentada é preferível a um heap sort que ninguém consegue auditar. Código que não se consegue ler não se consegue rever para segurança.

**Regra 4 — Algoritmos fancy são mais buggy e mais difíceis de acertar. Usa algoritmos simples e estruturas de dados simples.**
Uma `map[string]*rate.Limiter` protegida por mutex vence qualquer framework com strategy pattern. O atacante beneficia da tua complexidade.

**Regra 5 — Os dados dominam. Se escolheste as estruturas de dados certas, os algoritmos são auto-evidentes.**
Design começa nas structs, não nas funções. Uma `ReleaseDecision` bem definida torna o resto inevitável. Em segurança: uma struct de input bem modelada é a tua primeira linha de defesa.

---

## Effective Go — Regras de Ouro

**Aceita interfaces, retorna structs concretos** — define a interface no pacote *consumidor*, não no produtor.

**Erros são valores** — trata-os onde fazem sentido; um wrap com contexto útil na boundary do sistema. Nunca `_` em caminhos de segurança.

**Goroutines têm dono** — quem lança é responsável pelo ciclo de vida. `context` para cancelamento, `sync.WaitGroup` para join.

**Nomeação: clareza vence brevidade** — `validateBearerToken` em vez de `chkTkn`. Variáveis de escopo amplo precisam de nomes descritivos.

**Comentários em inglês seguindo godoc** — explica o *porquê*, não o *quê*.

```go
// Use constant-time comparison to prevent timing attacks.
return subtle.ConstantTimeCompare(a, b) == 1
```

**`any` em vez de `interface{}`** — Go 1.18+, usa o alias idiomático.

---

## Segurança como Cross-Cutting Concern

Segurança não é uma camada — é uma propriedade de cada decisão de design.

| Decisão | Princípio | Anti-padrão a evitar |
|---------|-----------|----------------------|
| Aleatoriedade | `crypto/rand` sempre | `math/rand` para tokens/IDs |
| Comparações | `crypto/subtle` | `==` em tokens (timing attack) |
| Context keys | tipo dedicado (`type ctxKey string`) | plain `string` (colisão silenciosa) |
| Segredos | `os.Getenv` + validação na startup | `.env` em produção, hardcode |
| Logging | `log/slog` estruturado | dep externa sem justificação; nunca logas tokens/PII |
| Dependências | stdlib primeiro | dep externa sem justificação explícita |

```go
// Context key tipada — nunca plain string.
type ctxKey string

const claimsKey ctxKey = "claims"

func withClaims(ctx context.Context, c *Claims) context.Context {
    return context.WithValue(ctx, claimsKey, c)
}

func claimsFromCtx(ctx context.Context) (*Claims, bool) {
    c, ok := ctx.Value(claimsKey).(*Claims)
    return c, ok
}
```

```go
// Logging estruturado com stdlib — sem dependência externa.
import "log/slog"

slog.Info("gate decision",
    "component",  "wardex",
    "decision",   decision.Action,
    "cvss",       score.CVSS,
    "epss",       score.EPSS,
    // nunca: token, password, secret
)
```

```go
// Segredos na startup — falha rápido, falha explicitamente.
func mustEnv(key string) string {
    v := os.Getenv(key)
    if v == "" {
        // panic na startup é correcto — não serves requests sem config válida
        panic(fmt.Sprintf("required env var %q is not set", key))
    }
    return v
}
```

---

## Padrões do Ecosistema

### CLI (Cobra)

```go
// Validação de flags antes de qualquer I/O.
var scanCmd = &cobra.Command{
    Use:   "scan [path]",
    Short: "Scan for exposed secrets",
    Args:  cobra.ExactArgs(1),
    RunE:  runScan, // RunE, não Run — erros propagam correctamente
}

func runScan(cmd *cobra.Command, args []string) error {
    root := args[0]

    // Valida o path antes de passar para o scanner.
    info, err := os.Stat(root)
    if err != nil {
        return fmt.Errorf("scan: invalid path: %w", err)
    }
    if !info.IsDir() {
        return fmt.Errorf("scan: %q is not a directory", root)
    }

    return scanner.Run(cmd.Context(), root)
}
```

### File Walking com Goroutines

```go
// Dono claro: Walk lança, WaitGroup faz join, errCh drena antes de retornar.
func walkFiles(ctx context.Context, root string, process func(string) error) error {
    var wg sync.WaitGroup
    errCh := make(chan error, 1) // buffered — não bloqueia o sender

    err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            return err
        }
        if d.IsDir() || !isTargetFile(d.Name()) {
            return nil
        }

        // Verifica cancelamento antes de lançar goroutine.
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        wg.Add(1)
        go func(p string) {
            defer wg.Done()
            if err := process(p); err != nil {
                select {
                case errCh <- err: // só o primeiro erro
                default:
                }
            }
        }(path)

        return nil
    })

    wg.Wait()
    close(errCh)

    if err != nil {
        return err
    }
    return <-errCh
}
```

### JSON Envelope entre Serviços (ex: Vexil → Wardex)

```go
// Estrutura de dados primeiro (Regra 5).
// O envelope define o contrato — a lógica é consequência.
type Finding struct {
    File    string  `json:"file"`
    Line    int     `json:"line"`
    Entropy float64 `json:"entropy"`
    Snippet string  `json:"snippet"` // nunca o valor completo
    RuleID  string  `json:"rule_id"`
}

type ScanEnvelope struct {
    Version   string    `json:"version"`
    Timestamp time.Time `json:"timestamp"`
    Findings  []Finding `json:"findings"`
    Summary   struct {
        Total    int `json:"total"`
        Critical int `json:"critical"`
    } `json:"summary"`
}

// Validação na boundary — antes de qualquer processamento.
func ParseEnvelope(r io.Reader) (*ScanEnvelope, error) {
    dec := json.NewDecoder(io.LimitReader(r, 10<<20)) // 10MB max
    dec.DisallowUnknownFields()

    var env ScanEnvelope
    if err := dec.Decode(&env); err != nil {
        return nil, fmt.Errorf("envelope: decode: %w", err)
    }
    if env.Version == "" {
        return nil, errors.New("envelope: missing version")
    }
    return &env, nil
}
```

### Validação de Path (universal — scanners, file servers, CLIs)

```go
// Path traversal é o bug mais comum em qualquer tool que toca ficheiros.
func safePath(base, input string) (string, error) {
    candidate := filepath.Join(base, filepath.Clean(input))
    if !strings.HasPrefix(candidate, base+string(filepath.Separator)) {
        return "", fmt.Errorf("path %q escapes base dir", input)
    }
    return candidate, nil
}
```

---

## Vulnerabilidades Comuns — Quick Reference

### Timing Attack
```go
// Nunca:  provided == stored
return subtle.ConstantTimeCompare([]byte(provided), []byte(stored)) == 1
```

### Command Injection
```go
// Nunca: exec.Command("sh", "-c", userInput)
// Sempre: argumentos separados + whitelist
cmd := exec.CommandContext(ctx, "ping", "-c", "1", validatedHost)
```

### Integer Overflow em alocações
```go
if size < 0 || size > maxAllowed {
    return nil, errors.New("invalid size")
}
buf := make([]byte, size)
```

### Race Condition
```go
// go test -race ./...  — corre sempre em CI
// sync.RWMutex para reads frequentes; sync.Mutex para writes dominantes
```

---

## Threat Modeling (STRIDE) — rápido

Para cada componente: **S**poofing · **T**ampering · **R**epudiation · **I**nformation Disclosure · **D**enial of Service · **E**levation of Privilege.

---

## Checklist antes de finalizar

- [ ] Erros tratados explicitamente — sem `_` em caminhos de segurança
- [ ] Goroutines têm dono e ciclo de vida definido
- [ ] `crypto/rand` para toda aleatoriedade segura
- [ ] `crypto/subtle` para comparações de segurança  
- [ ] Context keys são tipos dedicados, não strings
- [ ] Nenhuma dep externa sem necessidade demonstrada
- [ ] Logging com `log/slog` — sem tokens, passwords, PII
- [ ] Segredos via `os.Getenv` — sem hardcode, sem `.env` em prod
- [ ] `any` em vez de `interface{}`
- [ ] `go vet ./...` e `staticcheck ./...` passam limpos
- [ ] `go test -race ./...` sem data races

---

## Ferramentas

```bash
govulncheck ./...        # vulnerabilidades em dependências
gosec -fmt=json ./...    # análise estática de segurança
staticcheck ./...        # linter avançado
go test -race ./...      # detecção de race conditions
go vet ./...             # análise estática básica
```

---

## Referências

- https://go.dev/doc/effective_go
- https://google.github.io/styleguide/go/
- https://pkg.go.dev/log/slog
- https://golang.org/doc/security/
- https://github.com/securego/gosec
