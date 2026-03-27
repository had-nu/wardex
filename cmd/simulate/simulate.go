// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package simulate

import (
	"fmt"
	"os"

	"github.com/had-nu/wardex/test"
	"github.com/spf13/cobra"
)

var SimulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "Launch the Wardex Risk Simulator",
	Run: func(cmd *cobra.Command, args []string) {
		html := `<!DOCTYPE html>
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

		filename := "wardex-simulator.html"
		err := os.WriteFile(filename, []byte(html), 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating simulator file: %v\n", err)
			os.Exit(1)
		}

		wd, _ := os.Getwd()
		fullPath := wd + string(os.PathSeparator) + filename

		fmt.Printf("Wardex Risk Simulator generated successfully!\n")
		fmt.Printf("Open the following file in your web browser:\n\n")
		fmt.Printf("  file://%s\n\n", fullPath)
	},
}
