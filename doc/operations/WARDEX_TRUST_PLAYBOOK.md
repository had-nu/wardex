# Playbook Operacional: Wardex Trust Store & Sealed Config

Este guia descreve o fluxo completo de instalação e governação do sistema de confiança do Wardex para conformidade DORA.

---

## 1. Instalação do Wardex

### Opção A: Instalação via Go Install (Recomendado)
Para instalar a versão estável mais recente directamente do repositório:
```bash
go install github.com/had-nu/wardex@v1.9.0
```
*Nota: Certifica-te que `$(go env GOPATH)/bin` está no teu `$PATH`.*

### Opção B: Build a partir do Código Fonte (Desenvolvimento)
Se clonaste o repositório e queres compilar a versão local:
```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go build -o wardex .
# Move o binário para o teu PATH
sudo mv wardex /usr/local/bin/
```

---

## 2. Passo Inicial: Geração de Identidade
Antes de configurar o ambiente, precisas de uma identidade. O comando `keygen` cria automaticamente a pasta `~/.wardex` se ela não existir.

```bash
wardex keygen --out ~/.wardex/admin-key.wex
```
*   A pasta `~/.wardex` será criada com permissões `0700`.
*   A chave privada terá permissão `0400`.

---

## 3. Case 1: Bootstrap do Administrador (Local)

Nesta fase, ainda não existe um Trust Store remoto. O Administrador trabalha localmente.

### 3.1 Inicializar o Trust Store
```bash
wardex trust init \
  --keyring ~/.wardex/admin-key.wex \
  --actor admin@your-org.com \
  --name "Security Manager" \
  --out ./wardex-trust.yaml
```

### 3.2 Publicação e Activação
1.  Cria um repositório Git (ex: `wardex-governance`).
2.  Faz commit do `wardex-trust.yaml`.
3.  **Agora sim**, configura a variável de ambiente para o URL "Raw" do ficheiro:

**No teu `.bashrc` ou `.zshrc`:**
```bash
# Exemplo para GitHub
export WARDEX_TRUST_STORE="https://raw.githubusercontent.com/your-org/wardex-governance/main/wardex-trust.yaml"
```
*   **Importante**: Faz commit do `wardex-trust.yaml` para um repositório Git central com branch protection.

> [!TIP]
> **Dica de Fluxo**: Para as operações de Admin (add/revoke), recomenda-se estar dentro da pasta do repositório de governação local. Isso facilita o uso de caminhos relativos e o ciclo de `git commit` posterior.

---

## 4. Case 2: Onboarding de um Analista Júnior

### 4.1 Acção do Analista
O analista gera a sua chave e envia a **pública** (`.pub`) para o admin.
```bash
wardex keygen --out ~/.wardex/junior-key.wex
# Enviar ~/.wardex/junior-key.wex.pub para o admin
```

### 4.2 Acção do Admin
O admin adiciona o analista ao store oficial.
```bash
wardex trust add \
  --trust ./wardex-trust.yaml \
  --keyring ~/.wardex/admin-key.wex \
  --pubkey ~/.wardex/junior-key.wex.pub \
  --role analyst \
  --actor junior@your-org.com \
  --name "Junior Analyst"
```

---

## 5. Case 3: Rotação de Executivo (CISO)

### 5.1 Revogação do Antigo CISO
Identifica o ID do CISO (ex: `js-ciso-01`) no YAML e revoga-o.
```bash
wardex trust revoke \
  --trust ./wardex-trust.yaml \
  --keyring ~/.wardex/admin-key.wex \
  --id "js-ciso-01" \
  --reason "Executive departure - Role rotation"
```

### 5.2 Onboarding do Novo CISO
```bash
wardex trust add \
  --trust ./wardex-trust.yaml \
  --keyring ~/.wardex/admin-key.wex \
  --pubkey ./new-ciso.pub \
  --role ciso \
  --actor new-ciso@your-org.com \
  --name "Successor CISO"
```

---

## 6. Case 4: Selagem e Avaliação (Fluxo CI/CD)

### 6.1 O CISO Sela a Configuração
O CISO aprova o draft do `wardex-config.yaml` e gera o selo criptográfico.
```bash
wardex config seal \
  --keyring ~/.wardex/ciso-key.wex \
  --input wardex-config.yaml \
  --out wardex.wexstate
```

### 6.2 Execução no Pipeline
O pipeline verifica o selo contra o Trust Store remoto.
```bash
# Se o config não for um .wexstate válido, o --strict causa falha (exit 3)
wardex evaluate \
  --config wardex.wexstate \
  --evidence vulns.yaml \
  --strict \
  ./controls/*.yml
```
