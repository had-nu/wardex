// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package golden

import (
	"strings"
	"testing"
)

func TestNormaliseRules(t *testing.T) {
	t.Parallel()

	normaliser := Normaliser{
		TempDir: "/tmp/wardex-golden-42",
		Version: "0.0.0-golden",
		Rules:   []string{RuleTimestamps, RuleLogTimestamps, RuleTmpDir, RuleVersion},
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "timestamps with offset and fraction",
			input: "generated 2026-10-21T15:58:42.728491619+01:00",
			want:  "generated <TS>\n",
		},
		{
			name:  "timestamp with Z",
			input: "generated 2026-10-21T14:58:42Z",
			want:  "generated <TS>\n",
		},
		{
			name:  "several timestamps",
			input: "from 2026-10-21T14:58:42Z to 2026-10-21T15:58:42+01:00",
			want:  "from <TS> to <TS>\n",
		},
		{
			name:  "space-separated report timestamp",
			input: "Generated 2026-10-21 18:05:47 by wardex",
			want:  "Generated <TS> by wardex\n",
		},
		{
			name:  "Go log timestamp prefix",
			input: "2026/10/21 17:53:24 IPC engine started\nnext line",
			want:  "<TS> IPC engine started\nnext line\n",
		},
		{
			name:  "temporary directory",
			input: "open /tmp/wardex-golden-42/work/missing.yaml: no such file",
			want:  "open <TMP>/work/missing.yaml: no such file\n",
		},
		{
			name:  "version",
			input: "wardex version 0.0.0-golden",
			want:  "wardex version <VERSION>\n",
		},
		{
			name:  "CRLF becomes LF",
			input: "one\r\ntwo\r\n",
			want:  "one\ntwo\n",
		},
		{
			name:  "non JSON text is kept",
			input: "Error: boom",
			want:  "Error: boom\n",
		},
		{
			name:  "empty input stays empty",
			input: "",
			want:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := normaliser.Normalise(test.input)
			if err != nil {
				t.Fatalf("Normalise: %v", err)
			}
			if got != test.want {
				t.Fatalf("Normalise:\n got %q\nwant %q", got, test.want)
			}
		})
	}
}

func TestNormaliseJSONIsReindentedAndIdempotent(t *testing.T) {
	t.Parallel()

	normaliser := Normaliser{Rules: []string{RuleTimestamps}}
	input := `{"Summary":{"GeneratedAt":"2026-10-21T15:58:42Z","Total":93},"b":[1,2]}`

	first, err := normaliser.Normalise(input)
	if err != nil {
		t.Fatalf("Normalise: %v", err)
	}

	want := "{\n  \"Summary\": {\n    \"GeneratedAt\": \"<TS>\",\n    \"Total\": 93\n  },\n  \"b\": [\n    1,\n    2\n  ]\n}\n"
	if first != want {
		t.Fatalf("Normalise:\n got %q\nwant %q", first, want)
	}

	second, err := normaliser.Normalise(first)
	if err != nil {
		t.Fatalf("Normalise (second pass): %v", err)
	}
	if second != first {
		t.Fatalf("Normalise is not idempotent:\nfirst  %q\nsecond %q", first, second)
	}
}

func TestNormaliseRejectsUnknownRule(t *testing.T) {
	t.Parallel()

	_, err := Normaliser{Rules: []string{"map-order"}}.Normalise("x")
	if err == nil {
		t.Fatal("Normalise accepted an unknown rule")
	}
	if !strings.Contains(err.Error(), "map-order") {
		t.Fatalf("error does not name the rule: %v", err)
	}
}

func TestNormaliseRequiresRuleInputs(t *testing.T) {
	t.Parallel()

	if _, err := (Normaliser{Rules: []string{RuleTmpDir}}).Normalise("x"); err == nil {
		t.Fatal("tmpdir rule accepted an empty temporary directory")
	}
	if _, err := (Normaliser{Rules: []string{RuleVersion}}).Normalise("x"); err == nil {
		t.Fatal("version rule accepted an empty version")
	}
}
