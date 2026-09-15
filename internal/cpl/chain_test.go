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
	for range n {
		line := entryLine(prevHash)
		log = append(log, line...)
		content := line[:len(line)-1] // strip trailing \n to match bytes.Split behaviour
		prevHash = sha256Hex(content)
	}
	return log
}

func TestChainVerifyValid(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{name: "legacy genesis format", fixture: "audit_log_ok.jsonl"},
		{name: "runtime previous_entry_hash format", fixture: "audit_log_runtime_ok.jsonl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := mustReadFile(t, fixturePath(t, tt.fixture))
			ok, err := cpl.VerifyChain(log)
			if err != nil {
				t.Fatalf("verify chain: %v", err)
			}
			if !ok {
				t.Error("cadeia valida reportada como invalida")
			}
		})
	}
}

func TestChainVerifyTampered(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{name: "legacy genesis format", fixture: "audit_log_tampered.jsonl"},
		{name: "runtime previous_entry_hash format", fixture: "audit_log_runtime_tampered.jsonl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := mustReadFile(t, fixturePath(t, tt.fixture))
			ok, err := cpl.VerifyChain(log)
			if err != nil {
				t.Fatalf("verify chain: %v", err)
			}
			if ok {
				t.Error("cadeia adulterada reportada como valida")
			}
		})
	}
}

func TestChainGenesisEntry(t *testing.T) {
	singleValid := entryLine("genesis")
	ok, err := cpl.VerifyChain(singleValid)
	if err != nil || !ok {
		t.Errorf("entrada genesis valida rejeitada: err=%v ok=%v", err, ok)
	}

	runtimeGen := []byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated"}` + "\n")
	ok, err = cpl.VerifyChain(runtimeGen)
	if err != nil || !ok {
		t.Errorf("entrada genesis runtime rejeitada: err=%v ok=%v", err, ok)
	}

	singleBad := entryLine("sha256:00000000")
	ok, err = cpl.VerifyChain(singleBad)
	if err != nil || ok {
		t.Errorf("entrada genesis invalida aceite: err=%v ok=%v", err, ok)
	}
}

func TestChainLinkParsing(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantHash string
		wantGen  bool
	}{
		{name: "canonical absent = genesis", line: `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated"}`, wantGen: true},
		{name: "canonical empty = genesis", line: `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","previous_entry_hash":""}`, wantGen: true},
		{name: "canonical hash link", line: `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","previous_entry_hash":"abcd"}`, wantHash: "abcd"},
		{name: "legacy genesis marker", line: `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","prev_hash":"genesis"}`, wantGen: true},
		{name: "legacy hash link", line: `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","prev_hash":"deadbeef"}`, wantHash: "deadbeef"},
		{name: "canonical wins over legacy", line: `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","previous_entry_hash":"canon","prev_hash":"genesis"}`, wantHash: "canon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link, err := cpl.ParseChainLink([]byte(tt.line))
			if err != nil {
				t.Fatalf("parse chain link: %v", err)
			}
			if link.Hash != tt.wantHash {
				t.Errorf("hash = %q, want %q", link.Hash, tt.wantHash)
			}
			isGen, err := cpl.IsGenesis([]byte(tt.line))
			if err != nil {
				t.Fatalf("is genesis: %v", err)
			}
			if isGen != tt.wantGen {
				t.Errorf("is genesis = %v, want %v", isGen, tt.wantGen)
			}
		})
	}
}

func TestChainLargeCorpus(t *testing.T) {
	chain := generateValidChain(t, 500)
	ok, err := cpl.VerifyChain(chain)
	if err != nil || !ok {
		t.Errorf("corpus de 500 eventos falhou: err=%v ok=%v", err, ok)
	}
}
