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
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- React & ReactDOM -->
    <script src="https://unpkg.com/react@18/umd/react.development.js" crossorigin></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js" crossorigin></script>
    <!-- Babel for in-browser JSX transform -->
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <!-- Lucide Icons (Browser Script build) -->
    <script src="https://unpkg.com/lucide@latest"></script>
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
		err := os.WriteFile(filename, []byte(html), 0644)
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
