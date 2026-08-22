package cpl_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/had-nu/wardex/v2/internal/cpl"
)

func entryLine(prevHash string) []byte {
	return []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","prev_hash":"` + prevHash + `"}` + "\n")
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func generateValidChain(t *testing.T, n int) []byte {
	t.Helper()
	var log []byte
	prevHash := "genesis"
	for i := 0; i < n; i++ {
		line := entryLine(prevHash)
		log = append(log, line...)
		content := line[:len(line)-1] // strip trailing \n to match bytes.Split behaviour
		prevHash = sha256Hex(content)
	}
	return log
}

func TestChainVerifyValid(t *testing.T) {
	log := mustReadFile(t, fixturePath(t, "audit_log_ok.jsonl"))
	ok, err := cpl.VerifyChain(log)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !ok {
		t.Error("cadeia valida reportada como invalida")
	}
}

func TestChainVerifyTampered(t *testing.T) {
	log := mustReadFile(t, fixturePath(t, "audit_log_tampered.jsonl"))
	ok, err := cpl.VerifyChain(log)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if ok {
		t.Error("cadeia adulterada reportada como valida")
	}
}

func TestChainGenesisEntry(t *testing.T) {
	singleValid := entryLine("genesis")
	ok, err := cpl.VerifyChain(singleValid)
	if err != nil || !ok {
		t.Errorf("entrada genesis valida rejeitada: err=%v ok=%v", err, ok)
	}

	singleBad := entryLine("sha256:00000000")
	ok, err = cpl.VerifyChain(singleBad)
	if err != nil || ok {
		t.Errorf("entrada genesis invalida aceite: err=%v ok=%v", err, ok)
	}
}

func TestChainLargeCorpus(t *testing.T) {
	chain := generateValidChain(t, 500)
	ok, err := cpl.VerifyChain(chain)
	if err != nil || !ok {
		t.Errorf("corpus de 500 eventos falhou: err=%v ok=%v", err, ok)
	}
}
