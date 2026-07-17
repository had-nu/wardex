package provenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/v2/internal/cpl"
	"github.com/had-nu/wardex/v2/pkg/attest"
	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/trust"
	"github.com/spf13/cobra"
)

type attestFlags struct {
	inputFile  string
	outputFile string
	signKey    string
	keyring    string
	tool       string
	version    string
	label      string
	submit     bool
}

var attFlags attestFlags

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Create and sign a 3CP tool provenance attestation",
	Long: `Read an artifact file, compute its SHA-256 hash, and produce a signed
3CP tool provenance attestation (CBOR deterministic encoding).

The attestation binds tool identity, input/output hashes, and timestamp
to an Ed25519 signature from the trust store.

Output is a CBOR-serialized SignedAttestation written to the specified
output path.`,
	Args: cobra.ExactArgs(1),
	RunE: runAttest,
}

func init() {
	attestCmd.Flags().StringVar(&attFlags.inputFile, "input", "", "Input artifact file to attest (required)")
	attestCmd.Flags().StringVarP(&attFlags.outputFile, "output", "o", "wardex-attestation.cbor", "Output path for signed attestation")
	attestCmd.Flags().StringVar(&attFlags.signKey, "sign-key", "", "Path to Ed25519 private key for signing")
	attestCmd.Flags().StringVar(&attFlags.keyring, "keyring", "", "Path to private key (alias for --sign-key)")
	attestCmd.Flags().StringVar(&attFlags.tool, "tool", "", "Tool name (e.g. wardex-convert/grype)")
	attestCmd.Flags().StringVar(&attFlags.version, "version", "", "Tool version (e.g. 2.3.0)")
	attestCmd.Flags().StringVar(&attFlags.label, "label", "", "Optional attestation label")
	attestCmd.Flags().BoolVar(&attFlags.submit, "submit", false, "Submit attestation hash to 3CP provenance anchor after signing")
	_ = attestCmd.MarkFlagRequired("input")
	_ = attestCmd.MarkFlagRequired("sign-key")
	ProvenanceCmd.AddCommand(attestCmd)
}

func runAttest(cmd *cobra.Command, args []string) error {
	keyPath := attFlags.signKey
	if keyPath == "" {
		keyPath = attFlags.keyring
	}
	if keyPath == "" {
		return fmt.Errorf("--sign-key or --keyring is required")
	}

	priv, err := trust.LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	inputPath := args[0]
	if attFlags.inputFile != "" {
		inputPath = attFlags.inputFile
	}

	safePath, err := cli.SafePath(inputPath)
	if err != nil {
		return fmt.Errorf("input path: %w", err)
	}

	data, err := os.ReadFile(safePath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	inputHash := sha256.Sum256(data)
	outputHash := sha256.Sum256(data)

	a := attest.New(attFlags.tool, attFlags.version).
		SetInputHash(inputHash[:]).
		SetOutputHash(outputHash[:])

	if attFlags.label != "" {
		a.ConvertedBy = attFlags.label
	}

	pub := priv.Public().(ed25519.PublicKey)
	keyID := "ed25519:" + hex.EncodeToString(pub)

	signer := func(msg []byte) ([]byte, error) {
		return ed25519.Sign(priv, msg), nil
	}

	signed, err := a.Sign(signer, keyID)
	if err != nil {
		return fmt.Errorf("sign attestation: %w", err)
	}

	outData, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}

	if err := os.WriteFile(attFlags.outputFile, outData, 0600); err != nil {
		return fmt.Errorf("write attestation: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Signed attestation written to %s\n", attFlags.outputFile)
	fmt.Fprintf(cmd.OutOrStdout(), "  Tool:     %s %s\n", a.Tool, a.Version)
	fmt.Fprintf(cmd.OutOrStdout(), "  Key:      %s\n", keyID[:16]+"...")
	fmt.Fprintf(cmd.OutOrStdout(), "  Input:    %s\n", inputPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  Hash:     sha256:%x\n", inputHash)

	if attFlags.submit {
		anchorer, err := getAnchorer()
		if err != nil {
			return fmt.Errorf("provenance anchor: %w", err)
		}
		defer func() { _ = anchorer.Close() }()

		attestCBOR, err := signed.MarshalAttestationCBOR()
		if err != nil {
			return fmt.Errorf("marshal attestation for submission: %w", err)
		}

		cfgHash, err := cpl.ComputeConfigHash(inputHash[:], cpl.AlgoSHA256)
		if err == nil {
			signed.Attestation.ConfigHash = cfgHash
		}

		result, err := anchorer.SubmitAttested(cmd.Context(), inputHash[:], attFlags.label, attestCBOR)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "[WARN] Attestation submitted locally but anchor submission failed: %v\n", err)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  Anchored:  %s (block ~%d)\n", result.Label, result.BlockIndex)
	}

	return nil
}
