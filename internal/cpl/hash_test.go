package cpl_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/had-nu/wardex/v2/internal/cpl"
)

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "fixtures", "cpl", name)
}

func TestCanonicalConfigDeterminism(t *testing.T) {
	cases := []struct {
		name string
		a, b string
	}{
		{
			name: "keys in different order",
			a:    fixturePath(t, "config_canonical.yaml"),
			b:    fixturePath(t, "config_keys_unordered.yaml"),
		},
		{
			name: "comments removed",
			a:    fixturePath(t, "config_canonical.yaml"),
			b:    fixturePath(t, "config_with_comments.yaml"),
		},
		{
			name: "whitespace normalised",
			a:    fixturePath(t, "config_canonical.yaml"),
			b:    fixturePath(t, "config_with_whitespace.yaml"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawA := mustReadFile(t, tc.a)
			rawB := mustReadFile(t, tc.b)

			hashA, err := cpl.ComputeConfigHash(rawA, cpl.AlgoSHA256)
			if err != nil {
				t.Fatalf("hash A: %v", err)
			}
			hashB, err := cpl.ComputeConfigHash(rawB, cpl.AlgoSHA256)
			if err != nil {
				t.Fatalf("hash B: %v", err)
			}

			if hashA != hashB {
				t.Errorf("hashes diverge: %q != %q", hashA, hashB)
			}
		})
	}
}

func TestCanonicalConfigEnvVarsNotExpanded(t *testing.T) {
	withVar := []byte("threshold: ${RISK_THRESHOLD}\n")

	t.Setenv("RISK_THRESHOLD", "high")
	hashWithEnv, err := cpl.ComputeConfigHash(withVar, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("hash com env: %v", err)
	}

	t.Setenv("RISK_THRESHOLD", "critical")
	hashChangedEnv, err := cpl.ComputeConfigHash(withVar, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("hash env alterada: %v", err)
	}

	if hashWithEnv != hashChangedEnv {
		t.Error("hash mudou quando env var foi alterada: env vars estao a ser expandidas")
	}
}

func TestCanonicalConfigKnownVector(t *testing.T) {
	input := []byte("risk_appetite: low\nthresholds:\n  critical: 0\n  high: 2\n")

	const expected = "sha256:9fb10556b293b483c9ad27d8e6f2b3f1168368169ebdea3502006de93b5820ea"

	got, err := cpl.ComputeConfigHash(input, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if got != expected {
		t.Errorf("vector falhou:\n  got:  %s\n  want: %s", got, expected)
	}
}

func TestCanonicalConfigInvalidYAML(t *testing.T) {
	invalid := []byte("key: : invalid\n  badly: [nested")
	_, err := cpl.ComputeConfigHash(invalid, cpl.AlgoSHA256)
	if err == nil {
		t.Error("esperava erro em YAML malformado, obteve nil")
	}
}

func TestAlgorithmPrefixParsing(t *testing.T) {
	cases := []struct {
		input   string
		wantAlg cpl.Algorithm
		wantErr bool
	}{
		{"sha256:abc123", cpl.AlgoSHA256, false},
		{"blake3:abc123", cpl.AlgoBLAKE3, false},
		{"md5:abc123", cpl.AlgoUnknown, true},
		{"abc123", cpl.AlgoUnknown, true},
		{"", cpl.AlgoUnknown, true},
	}

	for _, tc := range cases {
		alg, err := cpl.ParseAlgorithmPrefix(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("%q: esperava erro, obteve nil", tc.input)
		}
		if !tc.wantErr && alg != tc.wantAlg {
			t.Errorf("%q: algoritmo errado: got %v want %v", tc.input, alg, tc.wantAlg)
		}
	}
}

func TestMixedAlgorithmLog(t *testing.T) {
	raw := mustReadFile(t, fixturePath(t, "config_canonical.yaml"))

	shaHash, err := cpl.ComputeConfigHash(raw, cpl.AlgoSHA256)
	if err != nil {
		t.Fatalf("sha256 hash: %v", err)
	}

	results, err := cpl.VerifyLinkWithConfig(
		[]byte(`{"ts":"2026-06-20T10:00:00Z","event":"gate.evaluated","config_hash":"`+shaHash+`"}`+"\n"),
		raw,
	)
	if err != nil {
		t.Fatalf("verify-link: %v", err)
	}
	for _, r := range results {
		if r.Status != cpl.StatusOK {
			t.Errorf("entrada %s: status inesperado %v", r.EntryTimestamp, r.Status)
		}
	}
}
