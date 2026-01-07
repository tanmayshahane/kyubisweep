// Package main is the entry point for KyubiSweep - a CLI tool to scan for exposed secrets.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tanmayshahane/kyubisweep/pkg/analyzer"
	"github.com/tanmayshahane/kyubisweep/pkg/quarantine"
	"github.com/tanmayshahane/kyubisweep/pkg/reporter"
	"github.com/tanmayshahane/kyubisweep/pkg/scanner"
)

const (
	numWorkers = 10

	bannerArt = `
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     🦊 KYUBISWEEP - Secret Scanner                            ║
    ║                                                               ║
    ║     Hunting exposed secrets with the cunning of a fox!        ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
`
)

func main() {
	// Define command-line flags
	scanPath := flag.String("path", ".", "Path to the directory to scan for secrets")
	verbose := flag.Bool("verbose", false, "Enable verbose output for debugging")
	showHelp := flag.Bool("help", false, "Show help information")
	allSeverity := flag.Bool("all", false, "Show all severity levels (default: HIGH only)")
	allFiles := flag.Bool("all-files", false, "Scan all files, not just text-based files")
	extraExt := flag.String("ext", "", "Additional file extensions to scan (comma-separated)")
	outputJSON := flag.Bool("json", false, "Output report as JSON file")
	noReport := flag.Bool("no-report", false, "Don't save report file")
	quiet := flag.Bool("quiet", false, "Minimal output, just summary stats")
	moveTo := flag.String("move-to", "", "Quarantine: Move files with secrets to this directory")

	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	startTime := time.Now()

	if !*quiet {
		fmt.Print(bannerArt)
	}

	absPath, err := filepath.Abs(*scanPath)
	if err != nil {
		fmt.Printf("❌ Error resolving path: %v\n", err)
		os.Exit(1)
	}

	if !*quiet {
		fmt.Printf("🔍 Scanning: %s\n", absPath)
		if *verbose {
			fmt.Println("📢 Verbose mode enabled")
		}
	}

	// Prepare extension filter
	var allowedExtensions map[string]bool
	if *allFiles {
		allowedExtensions = nil
	} else if *extraExt != "" {
		extras := strings.Split(*extraExt, ",")
		for i := range extras {
			extras[i] = strings.TrimSpace(extras[i])
		}
		allowedExtensions = scanner.MergeExtensions(extras)
	} else {
		allowedExtensions = scanner.DefaultTextExtensions
	}

	findings, fileCount := runScan(absPath, *verbose, *allSeverity, allowedExtensions)

	endTime := time.Now()

	// Create scan result
	result := reporter.ScanResult{
		ScanPath:     absPath,
		StartTime:    startTime,
		EndTime:      endTime,
		FilesScanned: fileCount,
		Findings:     findings,
	}

	// Print the Security Hygiene Scorecard
	reporter.PrintScorecard(result)

	// Save reports
	if !*noReport {
		if *outputJSON {
			saveJSONReport(result)
		} else {
			reportPath, err := reporter.SaveMarkdownReport(result, "reports")
			if err != nil {
				fmt.Printf("⚠️  Could not save report: %v\n", err)
			} else {
				fmt.Printf("  📁 Report saved: %s\n\n", reportPath)
			}
		}
	}

	// Handle quarantine if requested
	if *moveTo != "" && len(findings) > 0 {
		handleQuarantine(findings, *moveTo)
	}
}

func handleQuarantine(findings []analyzer.Finding, targetDir string) {
	// Get unique file paths
	uniqueFiles := make(map[string]bool)
	for _, f := range findings {
		uniqueFiles[f.FilePath] = true
	}

	filePaths := make([]string, 0, len(uniqueFiles))
	for path := range uniqueFiles {
		filePaths = append(filePaths, path)
	}

	// Ask for confirmation
	if !quarantine.ConfirmQuarantine(len(filePaths), targetDir) {
		fmt.Println("\n  ❌ Quarantine cancelled by user.")
		return
	}

	// Perform the quarantine
	fmt.Println("\n  📦 Moving files to quarantine...")

	results, err := quarantine.QuarantineFiles(filePaths, targetDir)
	if err != nil {
		fmt.Printf("  ❌ Quarantine failed: %v\n", err)
		return
	}

	// Show results
	quarantine.PrintQuarantineResults(results)
}

func printHelp() {
	fmt.Print(bannerArt)
	fmt.Println("USAGE:")
	fmt.Println("  kyubisweep [OPTIONS]")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("  --path <directory>   Path to scan (default: current directory)")
	fmt.Println("  --verbose            Enable detailed output")
	fmt.Println("  --all                Show all severity levels (default: HIGH only)")
	fmt.Println("  --all-files          Scan all files, not just text-based files")
	fmt.Println("  --ext <extensions>   Additional extensions to scan (comma-separated)")
	fmt.Println("  --json               Output report as JSON")
	fmt.Println("  --no-report          Don't save report file")
	fmt.Println("  --quiet              Minimal output, just summary")
	fmt.Println("  --move-to <path>     Move files with secrets to quarantine directory")
	fmt.Println("  --help               Show this help message")
	fmt.Println("")
	fmt.Println("EXAMPLES:")
	fmt.Println("  kyubisweep --path ./my-project")
	fmt.Println("  kyubisweep --path . --all")
	fmt.Println("  kyubisweep --path . --move-to ./secure_vault")
	fmt.Println("  kyubisweep --path . --json")
	fmt.Println("")
}

func runScan(rootPath string, verbose bool, showAll bool, allowedExtensions map[string]bool) ([]analyzer.Finding, int) {
	filePaths := make(chan string, 100)

	go func() {
		scanner.Walk(rootPath, filePaths, verbose, allowedExtensions)
		close(filePaths)
	}()

	results := make(chan analyzer.Finding, 100)
	fileCountCh := make(chan int, numWorkers)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()
			localCount := 0

			for filePath := range filePaths {
				localCount++
				if verbose {
					fmt.Printf("  [Worker %d] Analyzing: %s\n", workerID, filePath)
				}

				foundFindings := analyzer.AnalyzeFile(filePath)

				for _, finding := range foundFindings {
					results <- finding
				}
			}
			fileCountCh <- localCount
		}(i)
	}

	go func() {
		wg.Wait()
		close(results)
		close(fileCountCh)
	}()

	// Collect results
	var allFindings []analyzer.Finding
	for finding := range results {
		// Filter by severity if needed
		if !showAll && finding.Severity != "HIGH" {
			continue
		}
		allFindings = append(allFindings, finding)
	}

	// Count total files scanned
	totalFiles := 0
	for count := range fileCountCh {
		totalFiles += count
	}

	return allFindings, totalFiles
}

func saveJSONReport(result reporter.ScanResult) {
	reportsDir := "reports"
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		fmt.Printf("⚠️  Could not create reports directory: %v\n", err)
		return
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := filepath.Join(reportsDir, fmt.Sprintf("kyubisweep_%s.json", timestamp))

	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("⚠️  Could not save JSON report: %v\n", err)
		return
	}
	fmt.Printf("  📁 Report saved: %s\n\n", filename)
}
