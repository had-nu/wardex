// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package audit

import (
	"bytes"
	"encoding/csv"
	"testing"

	"github.com/had-nu/wardex/v3/pkg/auditlog"
)

func TestWriteCSVDecodesJSONValuesBeforeWriting(t *testing.T) {
	entry := auditlog.ExportEntry{Raw: []byte(`{"ts":"2026-09-24T00:00:00Z","detail":"quote \" slash \\ newline\nend","risk":1.25,"status":true,"config_hash":null}`)}
	var output bytes.Buffer
	if err := writeCSV(&output, []auditlog.ExportEntry{entry}); err != nil {
		t.Fatalf("writeCSV failed: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v\n%s", err, output.String())
	}
	if len(rows) != 2 {
		t.Fatalf("expected header and one row, got %d", len(rows))
	}
	values := make(map[string]string, len(rows[0]))
	for i, header := range rows[0] {
		values[header] = rows[1][i]
	}
	if values["detail"] != "quote \" slash \\ newline\nend" {
		t.Fatalf("JSON escapes were corrupted: %q", values["detail"])
	}
	if values["risk"] != "1.25" || values["status"] != "true" || values["config_hash"] != "" {
		t.Fatalf("non-string JSON values were not preserved: %#v", values)
	}
}
