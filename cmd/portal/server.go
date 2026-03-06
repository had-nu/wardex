package portal

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/spf13/cobra"
)

//go:embed static/*
var staticFS embed.FS

var PortalCmd = &cobra.Command{
	Use:   "portal",
	Short: "Start the local SaaS conversion and insights portal",
	Long: `portal launches a local web server (default port 8080) that serves
a sleek, interactive UI demonstrating the value of Wardex against public GitHub
repositories.

It clones repositories, runs standard security scanners, and visually compares
the naive CVSS findings with Wardex's contextual risk decisions in real-time.`,
	Run: runPortal,
}

func init() {
	PortalCmd.Flags().IntP("port", "p", 8080, "Port to listen on")
}

func runPortal(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetInt("port")

	// Strip the "static/" prefix from the embedded filesystem
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to initialize static assets: %v", err)
	}

	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/scan", handleScanAPI)
	mux.HandleFunc("/api/scan/", handleStreamAPI)

	// Serve static files (index.html, style.css, app.js)
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	addr := fmt.Sprintf("localhost:%d", port)

	fmt.Printf("\n[WARDEX] Portal starting on http://%s 🚀\n", addr)
	fmt.Printf("[WARDEX] Press Ctrl+C to stop.\n\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Portal server failed: %v", err)
	}
}
