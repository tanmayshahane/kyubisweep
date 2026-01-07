// Package reporter provides beautiful terminal output for KyubiSweep scan results.
// It uses ANSI escape codes for colors and text/tabwriter for aligned tables.
package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tanmayshahane/kyubisweep/pkg/analyzer"
	"github.com/tanmayshahane/kyubisweep/pkg/common"
)

// RiskLevel represents the severity with display properties
type RiskLevel struct {
	Name   string
	Color  string
	Icon   string
	Weight int
}

var (
	RiskCritical = RiskLevel{"CRITICAL", common.ColorRed + common.ColorBold, "🚨", 3}
	RiskHigh     = RiskLevel{"HIGH", common.ColorRed, "🔴", 2}
	RiskMedium   = RiskLevel{"MEDIUM", common.ColorYellow, "🟡", 1}
	RiskLow      = RiskLevel{"LOW", common.ColorBlue, "🔵", 0}
)

// ScanResult holds the complete scan information for reporting
type ScanResult struct {
	ScanPath     string
	StartTime    time.Time
	EndTime      time.Time
	FilesScanned int
	Findings     []analyzer.Finding
}

// PrintScorecard prints the Security Hygiene Scorecard to the terminal
func PrintScorecard(result ScanResult) {
	// Count findings by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, f := range result.Findings {
		switch f.Severity {
		case "HIGH":
			if isCriticalType(f.Type) {
				criticalCount++
			} else {
				highCount++
			}
		case "MEDIUM":
			mediumCount++
		default:
			lowCount++
		}
	}

	printHeader()
	printSummaryBanner(result, criticalCount, highCount, mediumCount, lowCount)

	if len(result.Findings) > 0 {
		printFindingsTable(result.Findings)
	}

	printFooter(result)
}

func isCriticalType(findingType string) bool {
	criticalTypes := []string{
		"AWS Access Key", "AWS Secret Access Key",
		"RSA Private Key", "SSH Private Key", "PGP Private Key",
		"GitHub Personal Access Token",
		"PostgreSQL Connection String", "MongoDB Connection String", "MySQL Connection String",
	}
	for _, t := range criticalTypes {
		if strings.Contains(findingType, t) {
			return true
		}
	}
	return false
}

func printHeader() {
	fmt.Println()
	fmt.Println(common.Colorize("╔══════════════════════════════════════════════════════════════════════════╗", common.ColorCyan))
	fmt.Println(common.Colorize("║", common.ColorCyan) + "                                                                          " + common.Colorize("║", common.ColorCyan))
	fmt.Println(common.Colorize("║", common.ColorCyan) + "     " + common.Bold("🛡️  KYUBISWEEP SECURITY HYGIENE SCORECARD") + "                            " + common.Colorize("║", common.ColorCyan))
	fmt.Println(common.Colorize("║", common.ColorCyan) + "                                                                          " + common.Colorize("║", common.ColorCyan))
	fmt.Println(common.Colorize("╚══════════════════════════════════════════════════════════════════════════╝", common.ColorCyan))
	fmt.Println()
}

func printSummaryBanner(result ScanResult, critical, high, medium, low int) {
	total := critical + high + medium + low

	var overallStatus string
	var statusColor string

	if critical > 0 {
		overallStatus = "🚨 CRITICAL ISSUES FOUND"
		statusColor = common.ColorRed + common.ColorBold
	} else if high > 0 {
		overallStatus = "⚠️  HIGH RISK DETECTED"
		statusColor = common.ColorRed
	} else if medium > 0 {
		overallStatus = "⚡ MODERATE ISSUES FOUND"
		statusColor = common.ColorYellow
	} else {
		overallStatus = "✅ ALL CLEAR - NO SECRETS DETECTED"
		statusColor = common.ColorGreen
	}

	fmt.Println(common.Colorize("  "+overallStatus, statusColor))
	fmt.Println()

	fmt.Println(common.Bold("  📊 RISK BREAKDOWN"))
	fmt.Println(common.Colorize("  ─────────────────────────────────────────", common.ColorDim))

	printRiskBar("CRITICAL", critical, total, common.ColorRed+common.ColorBold, "🚨")
	printRiskBar("HIGH", high, total, common.ColorRed, "🔴")
	printRiskBar("MEDIUM", medium, total, common.ColorYellow, "🟡")
	printRiskBar("LOW", low, total, common.ColorBlue, "🔵")

	fmt.Println()
}

func printRiskBar(label string, count int, total int, color string, icon string) {
	barWidth := 20
	filled := 0
	if total > 0 {
		filled = (count * barWidth) / max(total, 1)
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	countStr := fmt.Sprintf("%3d", count)

	fmt.Printf("  %s %-8s %s %s\n",
		icon,
		common.Colorize(label, color),
		common.Colorize(countStr, color),
		common.Colorize(bar, color))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printFindingsTable(findings []analyzer.Finding) {
	fmt.Println(common.Bold("  🔍 FINDINGS DETAIL"))
	fmt.Println(common.Colorize("  ─────────────────────────────────────────────────────────────────────────", common.ColorDim))
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "  %s\t%s\t%s\n",
		common.Bold("RISK"),
		common.Bold("TYPE"),
		common.Bold("LOCATION"))
	fmt.Fprintf(w, "  %s\t%s\t%s\n",
		"────────",
		"──────────────────────────────",
		"────────────────────────────────────────")

	displayCount := 0
	maxDisplay := 25

	for _, f := range findings {
		if displayCount >= maxDisplay {
			break
		}

		riskLabel := getRiskLabel(f)
		typeStr := truncate(f.Type, 30)
		locationStr := formatLocation(f.FilePath, f.LineNumber)

		fmt.Fprintf(w, "  %s\t%s\t%s\n", riskLabel, typeStr, locationStr)
		displayCount++
	}

	w.Flush()

	if len(findings) > maxDisplay {
		fmt.Printf("\n  %s\n", common.Colorize(fmt.Sprintf("  ... and %d more findings (see full report)", len(findings)-maxDisplay), common.ColorDim))
	}

	fmt.Println()
}

func getRiskLabel(f analyzer.Finding) string {
	switch f.Severity {
	case "HIGH":
		if isCriticalType(f.Type) {
			return common.Colorize("[CRITICAL]", common.ColorRed+common.ColorBold)
		}
		return common.Colorize("[HIGH]    ", common.ColorRed)
	case "MEDIUM":
		return common.Colorize("[MEDIUM]  ", common.ColorYellow)
	default:
		return common.Colorize("[LOW]     ", common.ColorBlue)
	}
}

func formatLocation(filePath string, lineNumber int) string {
	shortPath := filePath
	home, _ := os.UserHomeDir()
	if home != "" {
		shortPath = strings.Replace(filePath, home, "~", 1)
	}

	maxLen := 45
	if len(shortPath) > maxLen {
		shortPath = "..." + shortPath[len(shortPath)-maxLen+3:]
	}

	return fmt.Sprintf("%s:%d", shortPath, lineNumber)
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func printFooter(result ScanResult) {
	duration := result.EndTime.Sub(result.StartTime)

	fmt.Println(common.Colorize("  ─────────────────────────────────────────────────────────────────────────", common.ColorDim))

	scanPath := result.ScanPath
	home, _ := os.UserHomeDir()
	if home != "" {
		scanPath = strings.Replace(scanPath, home, "~", 1)
	}

	fmt.Printf("  📁 Scanned: %s\n", common.Bold(scanPath))
	fmt.Printf("  📄 Files analyzed: %s\n", common.Bold(formatNumber(result.FilesScanned)))
	fmt.Printf("  ⏱️  Duration: %s\n", common.Bold(formatDuration(duration)))
	fmt.Printf("  🕐 Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	fmt.Println(common.Colorize("  💡 Pro tip: Use --json to export findings for CI/CD integration", common.ColorDim))
	fmt.Println()
}

func formatNumber(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}

// SaveMarkdownReport saves a detailed markdown report to the reports folder
func SaveMarkdownReport(result ScanResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := filepath.Join(outputDir, fmt.Sprintf("kyubisweep_%s.md", timestamp))

	var sb strings.Builder
	sb.WriteString("# 🛡️ KyubiSweep Security Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s\n\n", timestamp))
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n\n", result.ScanPath))
	sb.WriteString(fmt.Sprintf("**Files Scanned:** %d\n\n", result.FilesScanned))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", formatDuration(result.EndTime.Sub(result.StartTime))))

	critical, high, medium, low := 0, 0, 0, 0
	for _, f := range result.Findings {
		switch f.Severity {
		case "HIGH":
			if isCriticalType(f.Type) {
				critical++
			} else {
				high++
			}
		case "MEDIUM":
			medium++
		default:
			low++
		}
	}

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| 🚨 CRITICAL | %d |\n", critical))
	sb.WriteString(fmt.Sprintf("| 🔴 HIGH | %d |\n", high))
	sb.WriteString(fmt.Sprintf("| 🟡 MEDIUM | %d |\n", medium))
	sb.WriteString(fmt.Sprintf("| 🔵 LOW | %d |\n", low))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", len(result.Findings)))

	if len(result.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		for i, f := range result.Findings {
			severity := f.Severity
			if isCriticalType(f.Type) && f.Severity == "HIGH" {
				severity = "CRITICAL"
			}
			sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, severity, f.Type))
			sb.WriteString(fmt.Sprintf("- **File:** `%s`\n", f.FilePath))
			sb.WriteString(fmt.Sprintf("- **Line:** %d\n", f.LineNumber))
			sb.WriteString(fmt.Sprintf("- **Match:** `%s`\n\n", truncate(f.Match, 4)))
		}
	}

	if err := os.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
		return "", err
	}

	return filename, nil
}
