package report

import (
	"fmt"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

// Generate delegates reporting based on the requested format.
func Generate(report model.GapReport, format string, outFile string) error {
	format = strings.ToLower(format)

	switch format {
	case "markdown":
		return generateMarkdown(report, outFile)
	case "json":
		return generateJSON(report, outFile)
	case "csv":
		return generateCSV(report, outFile)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}
