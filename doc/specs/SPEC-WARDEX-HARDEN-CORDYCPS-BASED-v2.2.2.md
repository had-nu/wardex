# Wardex CI/CD Hardening Specification
**WRDX-HARDEN-001 · v1.0 · 2026-06-28 · Status: IMPLEMENTED**

> **Implementação:** v2.2.2 (2026-06-29)
> - CI-1: [PR #96](https://github.com/had-nu/wardex/pull/96) — merged
> - CI-2: [PR #97](https://github.com/had-nu/wardex/pull/97) — merged
> - CI-3: [PR #98](https://github.com/had-nu/wardex/pull/98) — merged
> - Issue: [#94](https://github.com/had-nu/wardex/issues/94) — closed

Revisão de segurança pós-análise Cordyceps. Três findings, nenhum explorável pelo
padrão da Novee — mas dois deles contradizem o modelo que o Wardex defende para
clientes, e o terceiro expõe uma superfície que não foi testada.

---

## Enquadramento: o PPG interno

O Wardex é construído sobre uma tese concreta: organizações com baixa maturidade
sofrem de um Policy-Practice Gap — o que a função de segurança declara não
corresponde ao que efectivamente corre em produção. O `assess` detecta esse delta;
o `release gate` impede que ele se materialize em produção sem evidência explícita.

O `release.yml` contém exactamente esse delta. A política declarada é pinagem por
SHA em todas as dependências externas — e está implementada em todas as actions
do GitHub. A prática real instala o Syft via `curl | bash` apontado ao branch
`main` da anchore, sem hash, sem verificação. O mesmo artefacto que detectaria
este padrão num cliente não o detecta na sua própria pipeline de release.

Esta spec resolve os três findings por ordem de impacto, e inclui uma suite de
testes para o finding que tem maior superfície de ataque não explorada.

---

## CI-1 — Mutable install script (Syft · release.yml)

**Risco:** supply chain lateral. Se o repositório `anchore/syft` for comprometido
ou se o script em `main` for alterado entre commits, a próxima release do Wardex
instala código arbitrário no runner com permissões de escrita em GHCR e acesso ao
`GITHUB_TOKEN`. O Trivy e o cosign são pinados; o Syft não é. A assimetria não
tem justificação arquitectural.

**Correcção:** substituir o `curl | bash` por download do binário com verificação
SHA-256, usando o checksum publicado pela própria release da anchore.

```yaml
# release.yml — antes
- name: Install syft
  run: |
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# release.yml — depois
- name: Install syft
  env:
    SYFT_VERSION: "1.19.0"
    SYFT_SHA256: "b3f5f849d77c2c2d4bc42e9c96a7e0a99fee3f9e06ebd0b4e39c66d4e7a2d5a1"
  run: |
    curl -sSfL \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
      -o syft.tar.gz
    echo "${SYFT_SHA256}  syft.tar.gz" | sha256sum --check --strict
    tar -xzf syft.tar.gz syft
    install -m 0755 syft /usr/local/bin/syft
    rm syft.tar.gz syft
```

O hash `SYFT_SHA256` deve ser obtido da release page da anchore e versionado no
próprio ficheiro. A cada bump de versão, o hash actualiza junto. A alternativa
mais limpa — e que elimina a manutenção manual do hash — é substituir a instalação
directa pela action oficial:

```yaml
- name: Install syft
  uses: anchore/sbom-action/download-syft@v0.17.9  # pinado por SHA no repo
```

O SHA de pinagem do `anchore/sbom-action` é verificável da mesma forma que os
restantes — via `actions/checkout` e `git log`.

> **Nota de design — CI-1:** A correcção com `sha256sum` é deliberadamente verbosa
> para ficar visível no diff do PR. A alternativa mais elegante
> (`anchore/sbom-action/download-syft`) troca uma dependência mutable por uma
> action pinável, o que é mais coerente com o padrão já estabelecido nos outros
> steps. A escolha entre as duas depende de se queres controlo explícito da
> versão do Syft ou se preferes delegar à action da anchore. Para este PR,
> adoptámos o `sha256sum` para maximizar a visibilidade da mudança.

---

## CI-2 — Dev branch publica imagens não assinadas (docker.yml)

**Risco:** qualquer contribuidor com acesso de escrita ao branch `dev` pode
publicar uma imagem em `ghcr.io/had-nu/wardex` com a tag do SHA do commit. A
imagem não é assinada pelo cosign (a assinatura está condicional a
`startsWith(github.ref, 'refs/tags/')`). Utilizadores que façam `pull` por SHA
de commit recebem um artefacto sem atestação de integridade, sem SBOM, e sem
proveniência SLSA.

Há dois vectores distintos aqui. O primeiro é operacional: imagens de dev
published no mesmo registry que imagens de produção criam ambiguidade. O segundo
é arquitectural: o Wardex já implementa `wardex art14 verify` e `wardex accept
verify` para detectar artefactos adulterados — a sua própria imagem Docker deveria
ser sujeita ao mesmo nível de verificação.

**Correcção (mínima):** separar o push de imagens dev do push de imagens de
release com tags de namespace distintos, e aplicar assinatura a todos os builds
que passam pelo Trivy gate.

```yaml
# docker.yml — secção de metadata, depois
- name: Extract metadata
  id: meta
  uses: docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051 # v5
  with:
    images: ghcr.io/${{ github.repository }}
    tags: |
      type=semver,pattern={{version}}
      type=semver,pattern={{major}}.{{minor}}
      # dev builds ficam em namespace separado — não poluem o namespace de release
      type=ref,event=branch,prefix=dev-
      type=sha,format=long,prefix=sha-

# docker.yml — assinatura sem condicional de tag
- name: Sign image with cosign keyless
  run: |
    cosign sign ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }} --yes
```

A remoção do `if: startsWith(github.ref, 'refs/tags/')` garante que todos os
builds publicados ficam assinados, independentemente do trigger. O namespace
`dev-` isola visualmente imagens de desenvolvimento sem exigir um registry
separado.

---

## CI-3 — Validação de paths em action.yml

Este é o finding com maior superfície não testada. A `action.yml` passa cinco
inputs ao container wardex sem sanitização no layer YAML:

```
evaluate
  --evidence   ${{ inputs.evidence }}
  --config     ${{ inputs.config }}
  --framework  ${{ inputs.framework }}
  -o           ${{ inputs.output-format }}
  --out-file   ${{ inputs.output-file }}
```

Como o container recebe os args directamente (não via shell), injecção de comandos
clássica — `;rm -rf /`, `$(cmd)` — não funciona. O vector relevante é path
traversal: se o wardex CLI não valida os paths recebidos, um utilizador da
Marketplace Action pode:

- Ler ficheiros fora do workspace de CI com `--evidence ../../.env`
- Escrever outputs em localizações arbitrárias com `--out-file ../../.github/workflows/evil.yml`
- Expor segredos do runner via `--config /proc/self/environ` (em Linux runners)

### Função de validação a implementar

O CLI deve validar os paths de input e output antes de qualquer I/O. A função
abaixo é a referência que os testes verificam:

```go
// pkg/cli/pathguard.go

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ErrPathTraversal é devolvido quando um path tenta sair do directório base.
var ErrPathTraversal = errors.New("path traversal detected")

// ErrAbsolutePath é devolvido quando um path absoluto é recusado num contexto
// que exige paths relativos ao workspace.
var ErrAbsolutePath = errors.New("absolute path not permitted")

// ErrInvalidPath agrupa erros de inputs malformados (null bytes, strings
// inválidas UTF-8, paths excessivamente longos).
var ErrInvalidPath = errors.New("invalid path")

const (
	maxPathLen = 4096 // limite POSIX para nomes de path
)

// ValidateInputPath valida um path de ficheiro de input (--evidence, --config).
// base é o directório de trabalho; path é o valor fornecido pelo utilizador.
//
// Regras:
//   - paths absolutos são rejeitados
//   - paths que saem de base após resolução são rejeitados
//   - null bytes são rejeitados (os.Open em Go rejeita-os, mas queremos
//     devolver um erro explícito antes de qualquer syscall)
//   - strings com bytes UTF-8 inválidos são rejeitadas
//   - paths com comprimento superior a maxPathLen são rejeitados
//
// stdin ("-") é aceite e deve ser tratado pelo chamador.
func ValidateInputPath(base, path string) error {
	if path == "-" {
		return nil // stdin explicitamente permitido
	}
	return validatePath(base, path, false)
}

// ValidateOutputPath valida um path de ficheiro de output (--out-file).
// Aplica as mesmas regras que ValidateInputPath mas rejeita também paths
// para /dev/, /proc/, e /sys/ mesmo quando relativos ao workspace.
func ValidateOutputPath(base, path string) error {
	if err := validatePath(base, path, true); err != nil {
		return err
	}
	// Restrições adicionais para output: proteger pseudo-filesystems.
	abs, _ := filepath.Abs(filepath.Join(base, path))
	for _, prefix := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(abs, prefix) {
			return fmt.Errorf("%w: output to %s is not permitted", ErrAbsolutePath, prefix)
		}
	}
	return nil
}

func validatePath(base, path string, isOutput bool) error {
	if path == "" {
		return fmt.Errorf("%w: path must not be empty", ErrInvalidPath)
	}
	if len(path) > maxPathLen {
		return fmt.Errorf("%w: path exceeds %d bytes", ErrInvalidPath, maxPathLen)
	}
	// Null bytes: strings Go podem conter \x00; o kernel recusa-os, mas
	// queremos rejeitar explicitamente antes de qualquer I/O.
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: null byte in path", ErrInvalidPath)
	}
	// UTF-8 válido. Paths com bytes inválidos podem confundir log parsers.
	if !utf8.ValidString(path) {
		return fmt.Errorf("%w: invalid UTF-8 sequence", ErrInvalidPath)
	}

	// Paths absolutos são sempre recusados neste contexto.
	if filepath.IsAbs(path) {
		return fmt.Errorf("%w: %q", ErrAbsolutePath, path)
	}

	// Resolução e confinamento ao workspace.
	clean := filepath.Clean(filepath.Join(base, path))
	absBase, err := filepath.Abs(base)
	if err != nil {
		return fmt.Errorf("resolving workspace: %w", err)
	}
	if !strings.HasPrefix(clean, absBase+string(os.PathSeparator)) && clean != absBase {
		return fmt.Errorf("%w: %q resolves outside workspace", ErrPathTraversal, path)
	}
	return nil
}
```

> **Nota de design — CI-3 (symlinks):** A `ValidateInputPath` actual usa
> `filepath.EvalSymlinks` antes do prefix check. A implementação original
> (mostrada acima) usava `filepath.Clan` + prefix check, que *não* resolve
> symlinks — resolve apenas a componente sintáctica do path. Um symlink dentro
> do workspace que aponte para `/etc/passwd` passaria pelo check de prefix mas
> levaria o `os.Open` subsequente para fora do workspace. O código de
> implementação final acrescenta:
>
> ```go
> // Após filepath.Clean, resolver symlinks antes do prefix check.
> resolved, err := filepath.EvalSymlinks(clean)
> if err != nil {
>     // Ficheiro não existe ainda (output path) — aceitar o path sintáctico.
>     // Se for input, o os.Open vai falhar com erro mais informativo.
>     if !errors.Is(err, fs.ErrNotExist) {
>         return "", fmt.Errorf("resolving symlinks: %w", err)
>     }
>     resolved = clean
> }
> ```
>
> Além disso, paths absolutos fora do workspace são rejeitados com
> `ErrPathTraversal` em vez de `ErrAbsolutePath` — a validação verifica
> containment directamente sem joining, o que é mais robusto contra bypasses
> sintácticos.

### Suite de testes

```go
// pkg/cli/pathguard_test.go

package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/pkg/cli"
)

// setupWorkspace cria uma directoria temporária simulando o workspace de CI.
// Devolve o path absoluto e um cleanup func.
func setupWorkspace(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "wardex-pathguard-*")
	if err != nil {
		t.Fatalf("creating temp workspace: %v", err)
	}
	// Fixture: ficheiro legítimo no workspace
	if err := os.WriteFile(filepath.Join(dir, "vulns.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("creating fixture: %v", err)
	}
	// Subdir legítimo
	if err := os.MkdirAll(filepath.Join(dir, "reports"), 0o755); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}
	return dir, func() { os.RemoveAll(dir) }
}

func TestValidateInputPath(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	tests := []struct {
		name    string
		path    string
		wantErr error // nil = espera-se sucesso; erro sentinela específico
	}{
		// ── Inputs válidos ─────────────────────────────────────────────────
		{
			name: "valid_filename",
			path: "vulns.yaml",
		},
		{
			name: "valid_dotslash",
			path: "./vulns.yaml",
		},
		{
			name: "valid_subdir",
			path: "reports/scan.yaml",
		},
		{
			name: "stdin_dash",
			path: "-", // stdin é explicitamente aceite
		},

		// ── Path traversal ─────────────────────────────────────────────────
		{
			name:    "traversal_simple",
			path:    "../secret.yaml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_deep",
			path:    "../../../../../../../etc/passwd",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_embedded",
			path:    "reports/../../etc/shadow",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_with_dotslash",
			path:    "./../../.env",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name: "traversal_normalized_safe",
			// filepath.Clean normaliza "reports/../vulns.yaml" → "vulns.yaml" — deve passar
			path: "reports/../vulns.yaml",
			// Nota: este path normaliza-se para dentro do workspace; é válido.
			wantErr: nil,
		},
		{
			name:    "traversal_github_workflow",
			path:    "../../.github/workflows/ci.yml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "traversal_dotenv",
			path:    "../../.env",
			wantErr: cli.ErrPathTraversal,
		},

		// ── Paths absolutos ────────────────────────────────────────────────
		{
			name:    "absolute_etc_passwd",
			path:    "/etc/passwd",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "absolute_proc_environ",
			path:    "/proc/self/environ",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "absolute_proc_mem",
			path:    "/proc/self/mem",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "absolute_dev_null",
			path:    "/dev/null",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "absolute_dev_urandom",
			path:    "/dev/urandom",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "absolute_root",
			path:    "/",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "absolute_double_slash",
			path:    "//etc/passwd",
			wantErr: cli.ErrAbsolutePath,
		},

		// ── Inputs malformados ─────────────────────────────────────────────
		{
			name:    "empty_path",
			path:    "",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "null_byte_suffix",
			path:    "vulns.yaml\x00.evil",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "null_byte_prefix",
			path:    "\x00/etc/passwd",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "null_byte_middle",
			path:    "valid\x00../../etc/passwd",
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "path_too_long",
			path:    strings.Repeat("a/", 2100) + "file.yaml", // > 4096 bytes
			wantErr: cli.ErrInvalidPath,
		},
		{
			name:    "invalid_utf8",
			path:    "valid\xff\xfeinvalid.yaml",
			wantErr: cli.ErrInvalidPath,
		},

		// ── Tentativas de injecção de shell (inócuas em Docker mas testadas) ──
		// No contexto de container action, estes chegam como argv, não shell.
		// O wardex deve rejeitá-los igualmente — defesa em profundidade.
		{
			name:    "shell_semicolon",
			path:    "; cat /etc/passwd",
			wantErr: cli.ErrPathTraversal, // resolve fora do workspace
		},
		{
			name:    "shell_dollar_expansion",
			path:    "$(cat /etc/passwd).yaml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "shell_backtick",
			path:    "`whoami`.yaml",
			wantErr: cli.ErrPathTraversal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := cli.ValidateInputPath(base, tc.path)

			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateInputPath(%q) = %v; want nil", tc.path, err)
				}
				return
			}

			if err == nil {
				t.Errorf("ValidateInputPath(%q) = nil; want error wrapping %v", tc.path, tc.wantErr)
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateInputPath(%q) error type = %T (%v); want wrapping %v",
					tc.path, err, err, tc.wantErr)
			}
		})
	}
}

func TestValidateOutputPath(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		// ── Outputs válidos ────────────────────────────────────────────────
		{
			name: "valid_report",
			path: "wardex-report.md",
		},
		{
			name: "valid_subdir_report",
			path: "reports/wardex-report.json",
		},

		// ── Traversal em output — mais crítico: escrita arbitrária ─────────
		{
			name:    "output_traversal_workflow",
			path:    "../../.github/workflows/injected.yml",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "output_traversal_cron",
			path:    "../../../etc/cron.d/evil",
			wantErr: cli.ErrPathTraversal,
		},
		{
			name:    "output_traversal_ssh_authorized",
			path:    "../../../../root/.ssh/authorized_keys",
			wantErr: cli.ErrPathTraversal,
		},

		// ── Pseudo-filesystems — restrição adicional de output ─────────────
		{
			name:    "output_dev_stdout",
			path:    "/dev/stdout",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "output_proc_mem",
			path:    "/proc/self/mem",
			wantErr: cli.ErrAbsolutePath,
		},
		{
			name:    "output_sys_kernel",
			path:    "/sys/kernel/hostname",
			wantErr: cli.ErrAbsolutePath,
		},

		// ── Paths absolutos ────────────────────────────────────────────────
		{
			name:    "output_absolute_etc",
			path:    "/etc/wardex-poison.yaml",
			wantErr: cli.ErrAbsolutePath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := cli.ValidateOutputPath(base, tc.path)

			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateOutputPath(%q) = %v; want nil", tc.path, err)
				}
				return
			}

			if err == nil {
				t.Errorf("ValidateOutputPath(%q) = nil; want error wrapping %v", tc.path, tc.wantErr)
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateOutputPath(%q) error type = %T (%v); want wrapping %v",
					tc.path, err, err, tc.wantErr)
			}
		})
	}
}

// TestValidateInputPath_SymlinkEscape verifica que symlinks que apontam para
// fora do workspace são detectados. Este teste requer acesso ao filesystem.
func TestValidateInputPath_SymlinkEscape(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — symlink escape test skipped (root ignora DAC)")
	}

	base, cleanup := setupWorkspace(t)
	defer cleanup()

	// Cria um symlink dentro do workspace que aponta para fora.
	linkPath := filepath.Join(base, "escape-link.yaml")
	if err := os.Symlink("/etc/passwd", linkPath); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	// O path "escape-link.yaml" está dentro do workspace — mas o destino não.
	// A validação de path resolve o symlink; se não o fizer, este teste falha
	// e documenta a lacuna.
	err := cli.ValidateInputPath(base, "escape-link.yaml")

	// Comportamento esperado: ou o symlink é seguido e o destino é validado
	// (/etc/passwd está fora do workspace → ErrPathTraversal), ou o symlink
	// é recusado como categoria. Em qualquer caso, err != nil.
	if err == nil {
		t.Error("ValidateInputPath accepted a symlink pointing outside the workspace")
	}
}

// TestValidateInputPath_WorkspaceRoot verifica o edge case em que o path
// normaliza exactamente para o workspace root (não dentro dele).
func TestValidateInputPath_WorkspaceRoot(t *testing.T) {
	base, cleanup := setupWorkspace(t)
	defer cleanup()

	// "." normaliza para base — não é um ficheiro válido mas não é traversal.
	// O chamador deve rejeitar com "is a directory"; a validação de path
	// não deve devolver ErrPathTraversal.
	err := cli.ValidateInputPath(base, ".")
	if errors.Is(err, cli.ErrPathTraversal) {
		t.Errorf("ValidateInputPath(\".\") returned ErrPathTraversal; expected nil or other error")
	}
}
```

### Integração no Cobra RunE

A validação deve acontecer antes de qualquer abertura de ficheiro, no início do
`PreRunE` ou no início do `RunE`. Exemplo para o `evaluate` command:

```go
// cmd/evaluate.go (excerto)

func runEvaluate(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	// Validação de paths — fail fast, antes de qualquer I/O.
	if err := cli.ValidateInputPath(cwd, evidenceFlag); err != nil {
		return fmt.Errorf("--evidence: %w", err)
	}
	if err := cli.ValidateInputPath(cwd, configFlag); err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	if outFileFlag != "" {
		if err := cli.ValidateOutputPath(cwd, outFileFlag); err != nil {
			return fmt.Errorf("--out-file: %w", err)
		}
	}

	// ... resto da lógica de avaliação
}
```

---

## Matriz de verificação

| ID | Finding | Correcção | Como verificar |
|---|---|---|---|
| CI-1 | Syft install sem hash | Download pinado com `sha256sum` | `grep -E 'sha256\|sha256sum' .github/workflows/release.yml` |
| CI-2 | Imagens dev não assinadas | cosign em todos os builds; namespace `dev-` | `cosign verify ghcr.io/had-nu/wardex:dev-<sha>` |
| CI-3 | Sem validação de paths no CLI | `ValidateInputPath` / `ValidateOutputPath` | `go test ./pkg/cli/... -run TestValidatePath -v` |
| CI-3 | Cobertura da suite de testes | ≥ 90% no pacote `pkg/cli` | `go test -coverprofile=cov.out ./pkg/cli/... && go tool cover -func=cov.out` |
| CI-3 | Symlink escape | Symlink fora do workspace deve ser rejeitado | `go test ./pkg/cli/... -run TestValidateInputPath_SymlinkEscape -v` |

---

## Decisão de arquitectura a documentar

O finding CI-3 abre uma questão de design que deve ser respondida explicitamente
na `doc/architecture/` antes da próxima release da Marketplace Action:

**O wardex evaluate, quando invocado via Marketplace Action, opera em modo
confinado ao `GITHUB_WORKSPACE`?** Se sim, a validação de paths deve ser activada
automaticamente quando a variável de ambiente `GITHUB_WORKSPACE` está definida,
usando esse valor como `base` em vez de `os.Getwd()`. Se não, o README da action
deve documentar explicitamente que paths relativos são resolvidos em relação ao
working directory do container, e que paths fora do workspace não são bloqueados.

A ambiguidade actual é o que deixa o finding aberto: não porque o código esteja
errado, mas porque o contrato não está especificado. Wardex detecta este tipo de
lacuna em clientes — a `LayerDelta` entre o que a política declara e o que o
código implementa. O mesmo critério aplica-se aqui.

> **Nota de design — decisão arquitectural:** Este é o ponto mais importante da
> spec e o único que não tem correcção directa. A `action.yml` não especifica se
> o wardex corre confinado ao `GITHUB_WORKSPACE`. Enquanto esse contrato não
> estiver explícito, qualquer utilizador da Marketplace Action opera com
> expectativas não documentadas. A questão prática: quando
> `GITHUB_WORKSPACE=/home/runner/work/repo/repo` está definido, o `os.Getwd()`
> dentro do container não aponta necessariamente para ele — depende do
> `working-directory` declarado na action. Isso significa que a `base` usada na
> validação pode ser diferente do que o utilizador assume quando escreve
> `--evidence vulns.yaml`. O próximo passo é criar `WRDX-HARDEN-002` como issue
> no repo para resolver esta questão arquitectural.

---

*WRDX-HARDEN-001 · Root Security Governance Advisory · andre.ataide@proton.me*
