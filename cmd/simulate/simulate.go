// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package simulate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/had-nu/wardex/v2/pkg/cli"
	"github.com/had-nu/wardex/v2/pkg/ui"
	"github.com/had-nu/wardex/v2/test"
	"github.com/spf13/cobra"
)

var SimulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Launch the Wardex Risk Simulator",
	RunE:  runSimulate,
}

func runSimulate(cmd *cobra.Command, args []string) error {
	filename := "wardex-simulator.html"
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("simulate: determine output directory: %w", err)
	}
	outputPath := filepath.Join(wd, filename)

	stderr := cmd.ErrOrStderr()
	progress := ui.NewTerminalProgress(stderr)
	progress.Begin(buildSimulatorSession(outputPath))
	reportProgress := func(number int, name, status, detail string) {
		progress.Report(ui.PhaseEvent{
			Number: number,
			Name:   name,
			Status: status,
			Detail: detail,
		})
	}

	reportProgress(1, "Preparing simulator asset", "RUNNING", "")
	html := simulatorHTML()
	reportProgress(1, "Preparing simulator asset", "DONE", fmt.Sprintf("%d bytes", len(html)))

	reportProgress(2, "Writing simulator file", "RUNNING", filename)
	if err := cli.SafeWriteFile(filename, []byte(html)); err != nil {
		reportProgress(2, "Writing simulator file", "FAILED", err.Error())
		return fmt.Errorf("simulate: create simulator file: %w", err)
	}
	reportProgress(2, "Writing simulator file", "DONE", filename)

	reportProgress(3, "Finalizing simulator output", "RUNNING", "")
	reportProgress(3, "Finalizing simulator output", "DONE", "ready to open")

	if progress.Enabled() {
		renderSimulatorResults(stderr, progress, outputPath, len(html))
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Wardex Risk Simulator generated successfully!")
	fmt.Fprintln(cmd.OutOrStdout(), "Open the following file in your web browser:")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "  file://%s\n\n", outputPath)
	return nil
}

func simulatorHTML() string {
	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Wardex Risk Simulator</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com/3.4.1" integrity="sha384-SOMLQz+nKv/ORIYXo3J3NrWJ33oBgGvkHlV9t8i70QVLq8ZtST9Np1gDsVUkk4xN" crossorigin="anonymous"></script>
    <!-- React & ReactDOM -->
    <script src="https://unpkg.com/react@18.2.0/umd/react.development.js" integrity="sha384-0HL/VWVbwweJfp0saUL50fXRuSABCdVeinTBoJCDXprLkJ49VI0QMWNGMRt8ebnT" crossorigin="anonymous"></script>
    <script src="https://unpkg.com/react-dom@18.2.0/umd/react-dom.development.js" integrity="sha384-79Od0yhavbvtuP2nWl+Y6mwgs8AlknSIikYSw0+uOc65GTyH8SW7e2hCyCB303Y2" crossorigin="anonymous"></script>
    <!-- Babel for in-browser JSX transform -->
    <script src="https://unpkg.com/@babel/standalone@7.23.10/babel.min.js" integrity="sha384-KCD0A3BqTNZfWlXJcL7fKzDri97vicyNr4NUIr0vX6K9PZ0X5hOTeEbFh99jPEST" crossorigin="anonymous"></script>
    <!-- Lucide Icons (Browser Script build) -->
    <script src="https://unpkg.com/lucide@0.344.0/dist/umd/lucide.js" integrity="sha384-XH+ZCkuxxIrxQG0DVKQhb5v4zo16WNolye2PWC/djwSjCXKORYyqyF46I6Hoo0GT" crossorigin="anonymous"></script>
</head>
<body class="bg-gray-100">
    <div id="root"></div>
    <script type="text/babel">
` + test.SimulatorJSX + `
    const root = ReactDOM.createRoot(document.getElementById('root'));
    root.render(<WardexRiskSimulator />);
    </script>
</body>
</html>`
}
