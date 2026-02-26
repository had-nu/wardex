package report

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/had-nu/wardex/pkg/model"
)

func generateCSV(report model.GapReport, outFile string) error {
	var f *os.File
	var err error

	if outFile == "stdout" || outFile == "" {
		f = os.Stdout
	} else {
		f, err = os.Create(outFile)
		if err != nil {
			return fmt.Errorf("failed to create CSV file: %w", err)
		}
		defer f.Close()
	}

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{"Control ID", "Name", "Domain", "Status", "Score", "Gap Reasons"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, finding := range report.Findings {
		reasons := ""
		if len(finding.GapReasons) > 0 {
			reasons = finding.GapReasons[0] // Simplify for CSV
		}

		row := []string{
			finding.Control.ID,
			finding.Control.Name,
			finding.Control.Domain,
			string(finding.Status),
			fmt.Sprintf("%.2f", finding.FinalScore),
			reasons,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}
