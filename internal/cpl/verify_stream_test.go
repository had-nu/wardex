package cpl_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/internal/cpl"
)

// runtimeEntry builds a canonical-format entry body (no chain link yet).
func runtimeEntry(session string) string {
	return `{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","session_id":"` + session + `"}`
}

// runtimeChain builds a canonical chain, injecting each entry's
// previous_entry_hash as the SHA-256 of the preceding final line.
func runtimeChain(entries ...string) []byte {
	var log []byte
	prevHash := ""
	for i, e := range entries {
		line := []byte(e)
		if i > 0 {
			line = []byte(e[:len(e)-1] + `,"previous_entry_hash":"` + prevHash + `"}`)
		}
		log = append(log, line...)
		log = append(log, '\n')
		prevHash = sha256Hex(line)
	}
	return log
}

func TestVerifyStreamRuntimeValid(t *testing.T) {
	log := mustReadFile(t, fixturePath(t, "audit_log_runtime_ok.jsonl"))
	report, err := cpl.VerifyStream(bytes.NewReader(log), "")
	if err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	if !report.Valid {
		t.Error("cadeia runtime streamada reportada como invalida")
	}
	if report.Entries != 3 || len(report.Segments) != 1 {
		t.Errorf("esperado 1 segmento / 3 entradas, obtido %d / %d", len(report.Segments), report.Entries)
	}
}

func TestVerifyStreamLegacyValid(t *testing.T) {
	log := mustReadFile(t, fixturePath(t, "audit_log_ok.jsonl"))
	report, err := cpl.VerifyStream(bytes.NewReader(log), "")
	if err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	if !report.Valid {
		t.Error("cadeia legacy streamada reportada como invalida")
	}
}

func TestVerifyStreamTampered(t *testing.T) {
	log := mustReadFile(t, fixturePath(t, "audit_log_runtime_tampered.jsonl"))
	report, err := cpl.VerifyStream(bytes.NewReader(log), "")
	if err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	if report.Valid {
		t.Error("cadeia adulterada streamada reportada como valida")
	}
}

func TestVerifyStreamEmpty(t *testing.T) {
	_, err := cpl.VerifyStream(bytes.NewReader(nil), "")
	if err == nil {
		t.Error("log vazio deveria retornar erro")
	}
}

func TestVerifyStreamMultiSessionSegments(t *testing.T) {
	logA := runtimeChain(runtimeEntry("A"), runtimeEntry("A"))
	logB := runtimeChain(runtimeEntry("B"), runtimeEntry("B"))
	log := append(logA, logB...)

	report, err := cpl.VerifyStream(bytes.NewReader(log), "")
	if err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	if !report.Valid {
		t.Error("cadeia multi-sessao valida reportada como invalida")
	}
	if len(report.Segments) != 2 {
		t.Errorf("esperados 2 segmentos, obtidos %d", len(report.Segments))
	}
	if report.Entries != 4 {
		t.Errorf("esperadas 4 entradas, obtidas %d", report.Entries)
	}
}

func TestVerifyStreamSessionFilter(t *testing.T) {
	logA := runtimeChain(runtimeEntry("A"), runtimeEntry("A"))
	logB := runtimeChain(runtimeEntry("B"), runtimeEntry("B"))
	log := append(logA, logB...)

	report, err := cpl.VerifyStream(bytes.NewReader(log), "B")
	if err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	if !report.Valid || report.Entries != 2 || len(report.Segments) != 1 {
		t.Errorf("filtro por sessao inesperado: valid=%v entries=%d segments=%d", report.Valid, report.Entries, len(report.Segments))
	}
}

func TestVerifyStreamMalformedJSON(t *testing.T) {
	log := []byte("{not json}\n{ts: broken}\n")
	_, err := cpl.VerifyStream(bytes.NewReader(log), "")
	if err == nil {
		t.Error("JSON malformado deveria retornar erro estrutural")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("erro inesperado: %v", err)
	}
}
