package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

func generateJSON(report model.GapReport, outFile string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	if outFile == "stdout" || outFile == "" {
		fmt.Println(string(data))
		return nil
	}

	return os.WriteFile(outFile, data, 0644)
}
