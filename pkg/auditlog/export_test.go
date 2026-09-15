// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package auditlog_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/had-nu/wardex/v2/pkg/auditlog"
)

func chainLine(i int, prev string) string {
	return fmt.Sprintf(
		`{"ts":"2026-09-01T%02d:00:00Z","event":"gate.evaluated","config_hash":"cfg-%03d","previous_entry_hash":"%s"}`,
		i%24, i, prev,
	)
}

func chainHash(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

// buildChain returns a synthetic chained JSONL stream where link i references
// link i-1.
func buildChain(n int) []byte {
	var buf bytes.Buffer
	prev := ""
	for i := range n {
		line := chainLine(i, prev)
		buf.WriteString(line + "\n")
		prev = chainHash([]byte(line))
	}
	return buf.Bytes()
}

func TestExportLimitPlusOneHasMore(t *testing.T) {
	chain := buildChain(5)
	res, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{Limit: 3})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(res.Entries) != 3 {
		t.Errorf("entries = %d, esperado 3", len(res.Entries))
	}
	if !res.HasMore {
		t.Error("has_more devia ser true com 5 linhas e limit 3")
	}
	if res.NextCursor == "" {
		t.Error("next_cursor não devia ser vazio")
	}
	last := res.Entries[len(res.Entries)-1]
	if last.Hash != res.NextCursor {
		t.Errorf("next_cursor=%s != hash da última entrada %s", res.NextCursor, last.Hash)
	}
}

func TestExportLimitEqualsSizeNoMore(t *testing.T) {
	chain := buildChain(3)
	res, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{Limit: 3})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(res.Entries) != 3 {
		t.Errorf("entries = %d, esperado 3", len(res.Entries))
	}
	if res.HasMore {
		t.Error("has_more devia ser false quando o limite é exacto")
	}
}

func TestExportResumeByCursor(t *testing.T) {
	chain := buildChain(6)
	page1, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{Limit: 2})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}

	page2, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{Limit: 2, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Entries) != 2 {
		t.Fatalf("page2 entries = %d", len(page2.Entries))
	}
	if page2.Entries[0].PrevHash != page1.NextCursor {
		t.Errorf("retoma não encadeia: prev=%s cursor=%s", page2.Entries[0].PrevHash, page1.NextCursor)
	}
	if !page2.HasMore {
		t.Error("page2 devia ter mais entradas (6 total, 4 entregues)")
	}

	page3, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{Limit: 5, Cursor: page2.NextCursor})
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3.Entries) != 2 {
		t.Errorf("page3 entries = %d, esperado 2", len(page3.Entries))
	}
	if page3.HasMore {
		t.Error("page3 devia ser a última página")
	}
}

func TestExportCursorTamperedDetection(t *testing.T) {
	chain := buildChain(4)
	// Corrupt the entry after the first page: break its previous_entry_hash.
	lines := strings.Split(strings.TrimSpace(string(chain)), "\n")
	lines[1] = chainLine(1, "deadbeef")

	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l + "\n")
	}

	page1, err := auditlog.Export(bytes.NewReader(buf.Bytes()), auditlog.ExportOptions{Limit: 1})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	_, err = auditlog.Export(bytes.NewReader(buf.Bytes()), auditlog.ExportOptions{Limit: 5, Cursor: page1.NextCursor})
	if err == nil {
		t.Fatal("retoma após tamper devia falhar")
	}
	if !errors.Is(err, auditlog.ErrChainTampered) {
		t.Errorf("erro devia ser ErrChainTampered, veio %v", err)
	}
}

func TestExportCursorNotFound(t *testing.T) {
	chain := buildChain(2)
	_, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{
		Limit:  2,
		Cursor: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("cursor não existente devia falhar")
	}
}

func TestExportTailReturnsLastN(t *testing.T) {
	chain := buildChain(6)
	res, err := auditlog.Export(bytes.NewReader(chain), auditlog.ExportOptions{Limit: 2, Tail: true})
	if err != nil {
		t.Fatalf("export tail: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("tail entries = %d, esperado 2", len(res.Entries))
	}
	if res.HasMore {
		t.Error("tail não devia reportar has_more")
	}
	if res.NextCursor == "" {
		t.Error("tail next_cursor não devia ser vazio")
	}
}
