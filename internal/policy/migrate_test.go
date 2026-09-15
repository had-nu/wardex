package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/internal/policy"
)

const minValidDomain = `framework: iso27001
domain: technological_controls
controls:
  - id: A.8.1
    title: User endpoint devices
    status: compliant
`

func writeDomain(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "domain.yml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoadDomainLegacyV1MigratesInMemory(t *testing.T) {
	path := writeDomain(t, minValidDomain)
	d, err := policy.LoadDomain(path)
	if err != nil {
		t.Fatalf("load legacy domain: %v", err)
	}
	if d.FormatVersion != policy.CurrentFormatVersion {
		t.Errorf("legacy v1 migrado para v%d, obtido v%d", policy.CurrentFormatVersion, d.FormatVersion)
	}
	// P4: origin must not be mutated.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read origin: %v", err)
	}
	if strings.Contains(string(raw), "format_version") {
		t.Error("origem foi mutada com format_version")
	}
}

func TestLoadDomainExplicitV1Migrates(t *testing.T) {
	content := "format_version: 1\n" + minValidDomain
	path := writeDomain(t, content)
	d, err := policy.LoadDomain(path)
	if err != nil {
		t.Fatalf("load explicit v1 domain: %v", err)
	}
	if d.FormatVersion != policy.CurrentFormatVersion {
		t.Errorf("v1 explicito migrado para v%d, obtido v%d", policy.CurrentFormatVersion, d.FormatVersion)
	}
}

func TestLoadDomainCurrentV2(t *testing.T) {
	content := "format_version: 2\n" + minValidDomain
	path := writeDomain(t, content)
	d, err := policy.LoadDomain(path)
	if err != nil {
		t.Fatalf("load v2 domain: %v", err)
	}
	if d.FormatVersion != 2 {
		t.Errorf("v2 esperado, obtido v%d", d.FormatVersion)
	}
}

func TestLoadDomainV2RejectsUnknownField(t *testing.T) {
	content := "format_version: 2\norganization: orphan\n" + minValidDomain
	path := writeDomain(t, content)
	_, err := policy.LoadDomain(path)
	if err == nil {
		t.Fatal("v2 com campo desconhecido deveria falhar (discriminar typo)")
	}
}

func TestLoadDomainFutureVersionRejected(t *testing.T) {
	content := "format_version: 99\n" + minValidDomain
	path := writeDomain(t, content)
	_, err := policy.LoadDomain(path)
	if err == nil {
		t.Fatal("formato futuro deveria ser rejeitado explicitamente")
	}
}

func TestMigrateMissingStepErrors(t *testing.T) {
	d := &policy.DomainFile{FormatVersion: 0}
	if err := policy.Migrate(d, policy.CurrentFormatVersion); err == nil {
		t.Fatal("migracao a partir de v0 invalida deveria falhar")
	}
	d = &policy.DomainFile{FormatVersion: 99}
	if err := policy.Migrate(d, policy.CurrentFormatVersion); err == nil {
		t.Fatal("migracao de versao futura deveria falhar")
	}
}

func TestTheCurrentVersionIsOneWeSupport(t *testing.T) {
	content := "format_version: 2\n" + minValidDomain
	path := writeDomain(t, content)
	d, err := policy.LoadDomain(path)
	if err != nil {
		t.Fatalf("versao corrente deveria ser suportada: %v", err)
	}
	if d.FormatVersion != policy.CurrentFormatVersion {
		t.Errorf("versao corrente %d != suportada %d", d.FormatVersion, policy.CurrentFormatVersion)
	}
}
