// Package quarantine provides secure file relocation capabilities.
// It moves sensitive files containing secrets to a secure vault location.
package quarantine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tanmayshahane/kyubisweep/pkg/common"
)

// MoveResult represents the outcome of a file move operation
type MoveResult struct {
	OriginalPath string
	NewPath      string
	Success      bool
	Error        error
}

// QuarantineFiles moves files containing secrets to a secure target directory.
// It creates the target directory if it doesn't exist and handles naming collisions.
//
// IMPORTANT: This MOVES files (cut/paste), not copies. Original files are removed.
func QuarantineFiles(filePaths []string, targetDir string) ([]MoveResult, error) {
	// Create target directory if it doesn't exist
	if err := os.MkdirAll(targetDir, 0700); err != nil { // 0700 = owner-only access
		return nil, fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	results := make([]MoveResult, 0, len(filePaths))

	// Track files we've already moved to avoid duplicates
	movedFiles := make(map[string]bool)

	for _, srcPath := range filePaths {
		// Skip if we already processed this file
		if movedFiles[srcPath] {
			continue
		}
		movedFiles[srcPath] = true

		result := MoveResult{OriginalPath: srcPath}

		// Get the filename
		filename := filepath.Base(srcPath)

		// Determine target path, handling collisions
		targetPath := filepath.Join(targetDir, filename)
		targetPath = resolveCollision(targetPath)

		// Attempt to move the file
		err := moveFile(srcPath, targetPath)
		if err != nil {
			result.Success = false
			result.Error = err
		} else {
			result.Success = true
			result.NewPath = targetPath
		}

		results = append(results, result)
	}

	return results, nil
}

// resolveCollision adds a timestamp to filename if it already exists
func resolveCollision(targetPath string) string {
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return targetPath // File doesn't exist, no collision
	}

	// File exists, add timestamp
	dir := filepath.Dir(targetPath)
	ext := filepath.Ext(targetPath)
	nameWithoutExt := strings.TrimSuffix(filepath.Base(targetPath), ext)

	timestamp := time.Now().Format("20060102_150405")
	newName := fmt.Sprintf("%s_%s%s", nameWithoutExt, timestamp, ext)

	return filepath.Join(dir, newName)
}

// moveFile moves a file from src to dst.
// It first tries os.Rename (fast, same filesystem).
// If that fails (cross-filesystem), it falls back to copy+delete.
func moveFile(src, dst string) error {
	// Try the fast path first: os.Rename
	err := os.Rename(src, dst)
	if err == nil {
		return nil // Success!
	}

	// os.Rename failed - likely cross-filesystem move
	// Fall back to copy + delete
	return copyAndDelete(src, dst)
}

// copyAndDelete copies a file then deletes the original.
// Used when os.Rename fails (e.g., cross-filesystem moves).
func copyAndDelete(src, dst string) error {
	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Get source file info for permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// Create destination file
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// Copy contents
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	// Ensure all data is written
	err = dstFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	// Close files before deleting
	srcFile.Close()
	dstFile.Close()

	// Delete the original
	err = os.Remove(src)
	if err != nil {
		return fmt.Errorf("copied successfully but failed to delete original: %w", err)
	}

	return nil
}

// ConfirmQuarantine displays a warning and asks for user confirmation.
// Returns true if user confirms, false otherwise.
func ConfirmQuarantine(fileCount int, targetDir string) bool {
	fmt.Println()
	fmt.Println(common.ColorRed + common.ColorBold + "╔══════════════════════════════════════════════════════════════════════════╗" + common.ColorReset)
	fmt.Println(common.ColorRed + common.ColorBold + "║                           ⚠️  WARNING ⚠️                                   ║" + common.ColorReset)
	fmt.Println(common.ColorRed + common.ColorBold + "╚══════════════════════════════════════════════════════════════════════════╝" + common.ColorReset)
	fmt.Println()
	fmt.Println(common.ColorRed + common.ColorBold + "  This operation will MOVE files from their original location." + common.ColorReset)
	fmt.Println(common.Red("  They will NO LONGER EXIST in the source directories."))
	fmt.Println()
	fmt.Printf("  📁 Files to move: %s%d%s\n", common.ColorBold, fileCount, common.ColorReset)
	fmt.Printf("  📂 Target vault:  %s%s%s\n", common.ColorBold, targetDir, common.ColorReset)
	fmt.Println()
	fmt.Println(common.Yellow("  This action cannot be easily undone!"))
	fmt.Println()
	fmt.Print("  Type 'yes' to confirm, or anything else to cancel: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}

// PrintQuarantineResults displays the results of a quarantine operation
func PrintQuarantineResults(results []MoveResult) {
	fmt.Println()
	fmt.Println(common.Bold("  📦 QUARANTINE RESULTS"))
	fmt.Println("  ─────────────────────────────────────────────────────────────────────────")

	successCount := 0
	failCount := 0

	for _, r := range results {
		if r.Success {
			successCount++
			fmt.Printf("  %s Moved: %s\n", common.Green("✅"), shortenPath(r.OriginalPath))
			fmt.Printf("     → %s\n", shortenPath(r.NewPath))
		} else {
			failCount++
			fmt.Printf("  %s Failed: %s\n", common.Red("❌"), shortenPath(r.OriginalPath))
			fmt.Printf("     Error: %v\n", r.Error)
		}
	}

	fmt.Println()
	if failCount == 0 {
		fmt.Printf("  %s Successfully quarantined %d file(s)\n", common.Green("✅"), successCount)
	} else {
		fmt.Printf("  ⚠️  Moved: %d | Failed: %d\n", successCount, failCount)
	}
	fmt.Println()
}

func shortenPath(path string) string {
	home, _ := os.UserHomeDir()
	if home != "" {
		path = strings.Replace(path, home, "~", 1)
	}
	if len(path) > 60 {
		return "..." + path[len(path)-57:]
	}
	return path
}
