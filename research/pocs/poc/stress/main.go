package main

import (
	"fmt"
	"os"
)

func main() {
	f, _ := os.Create("stress-vulns.yaml")
	defer func() { _ = f.Close() }()

	_, _ = fmt.Fprint(f, "vulnerabilities:\n")
	for i := 1; i <= 250; i++ {
		// Real CVE pattern, pseudo-randomized years to ensure FIRST has diverse hits
		year := 2018 + (i % 6)
		_, _ = fmt.Fprintf(f, "  - cve_id: \"CVE-%d-%05d\"\n", year, i*13)
		_, _ = fmt.Fprintf(f, "    severity: \"CRITICAL\"\n")
		_, _ = fmt.Fprintf(f, "    cvss_base: 9.8\n")
		_, _ = fmt.Fprintf(f, "    epss_score: 0.0\n")
		_, _ = fmt.Fprintf(f, "    products:\n")
		_, _ = fmt.Fprintf(f, "      - \"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0\"\n")
	}
	fmt.Println("stress-vulns.yaml generated with 250 CVEs.")
}
