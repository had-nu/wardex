package ui

import (
	"fmt"
	"time"
)

// ANSI color codes for the aesthetic
const (
	dim       = "\033[38;5;236m"
	dimLine   = "\033[38;5;235m" // Very dark gray for separator lines
	dimPurple = "\033[38;5;55m"
	purple    = "\033[38;2;170;0;255m"
	grey      = "\033[38;2;170;170;170m"
	pink      = "\033[38;2;255;0;127m"
	cyan      = "\033[38;5;51m"
	green     = "\033[38;5;46m"
	yellow    = "\033[38;5;226m"
	white     = "\033[38;5;255m"
	reset     = "\033[0m"
)

// smoothGradient generates an extremely smooth purple horizontal gradient for the background code.
func smoothGradient(text string, startPcnt, endPcnt float64) string {
	var out string
	rs := []rune(text)
	if len(rs) == 0 {
		return ""
	}
	for i, r := range rs {
		ratio := startPcnt + (endPcnt-startPcnt)*(float64(i)/float64(len(rs)))
		if ratio > 1 {
			ratio = 1
		}
		if ratio < 0 {
			ratio = 0
		}

		// Map ratio linearly:
		// Deep Cyber Purple (45, 10, 85) -> Vibrant Magenta/Pink Context (160, 0, 150)
		red := 45 + int(ratio*115)
		green := 10 - int(ratio*10)
		blue := 85 + int(ratio*65)

		out += fmt.Sprintf("\033[38;2;%d;%d;%dm%c", red, green, blue, r)
	}
	return out + reset
}

// PrintBanner outputs the Wardex CLI startup banner with a "code-behind"
// dark aesthetic mimicking the requested ASCII style layout.
func PrintBanner() {
	now := time.Now().Format("15:04:05.000")
	tStamp := fmt.Sprintf("%s[%s]%s", pink, now, reset)

	lineSep := fmt.Sprintf("%s-------------------------------------------------------------------------------------------------------%s", purple, reset)

	// --- Top Section: Compact Code & Logs ---
	fmt.Printf("\n%s\n", smoothGradient("func (g *Gate) Evaluate(ctx context.Context) (*Decision, error) {", 0.0, 0.4))
	fmt.Printf("%s %sSYSTEM_INIT%s   Ω :: W A R D E X v2.1.0\n", tStamp, cyan, reset)
	fmt.Printf("%s\n", lineSep)

	// --- Middle Section: Elegant Simple Logo over Dim Code ---
	logo := []string{
		`  ◈  W A R D E X                      `,
		`  │  Risk-Based Release Gate          `,
		`  └─────────────────────────────────  `,
	}

	bgContexts := []string{
		`SUB RSP, 0x28                   `,
		`score := g.RiskEngine.Score()   `,
		`package wardex (import)         `,
	}

	bgContextsRight := []string{
		` // 0x488B05           `,
		` ; check thresholds    `,
		` ; end frame           `,
	}

	for i := 0; i < 3; i++ {
		leftBgRaw := fmt.Sprintf("%-35s", bgContexts[i])
		leftBgHtml := smoothGradient(leftBgRaw, 0.0, 0.35)

		rightBgRaw := bgContextsRight[i]
		rightBgHtml := smoothGradient(rightBgRaw, 0.75, 1.0)

		// Colorize the logo elegantly
		logoLine := ""
		if i == 0 {
			logoLine = fmt.Sprintf("%s%s%s", pink, logo[i], reset)
		} else if i == 1 {
			logoLine = fmt.Sprintf("%s%s%s", cyan, logo[i], reset)
		} else {
			logoLine = fmt.Sprintf("%s%s%s", dimPurple, logo[i], reset)
		}

		fmt.Printf("%s%s   %s\n", leftBgHtml, logoLine, rightBgHtml)
	}

	// --- Bottom Section: Lower Context & Final Status ---
	fmt.Printf("%s\n", smoothGradient("    if score > g.Threshold { return Deny, nil }", 0.1, 0.4))

	fmt.Printf("%s[RISK-BASED]%s %sscore%s %s[RELEASE-GATE]%s %s0x8B2E%s %s0xRBRG-v2.1%s\n",
		white, reset, dim, reset, cyan, reset, dim, reset, yellow, reset)

	fmt.Printf("%s\n", lineSep)

	fmt.Printf("%s %sGATE_STATUS%s   :: %sACTIVE%s       [%s█████████████████████████░░%s]  93%%\n",
		tStamp, white, reset, pink, reset, pink, reset)
	fmt.Printf("%s %sRISK_ENGINE%s   :: %sONLINE%s       %sTHRESHOLD=0.72  VECTORS=14  ASSETS=203%s\n",
		tStamp, cyan, reset, green, reset, dim, reset)
	fmt.Printf("%s %sPIPELINE%s      :: %sAWAITING_RELEASE_TOKEN%s\n",
		tStamp, dimPurple, reset, yellow, reset)

	fmt.Printf("%s\n\n", lineSep)
}
