package quarantine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// TEST: QuarantineFiles
// Uses t.TempDir() for integration testing with real filesystem
// =============================================================================

func TestQuarantineFiles(t *testing.T) {
	// t.TempDir() creates a temporary directory that is automatically
	// cleaned up when the test completes. No manual cleanup needed!
	sourceDir := t.TempDir()
	targetDir := t.TempDir()

	// Create a test file in source directory
	testFileName := "secret.txt"
	testFilePath := filepath.Join(sourceDir, testFileName)
	testContent := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE")

	err := os.WriteFile(testFilePath, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Verify the file exists in source
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Fatal("Test file should exist in source before quarantine")
	}

	// Mock user input: "y" to delete original
	oldInput := inputReader
	inputReader = strings.NewReader("y\n")
	defer func() { inputReader = oldInput }()

	// Perform the quarantine
	results, err := QuarantineFiles([]string{testFilePath}, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles failed: %v", err)
	}

	// Verify we got one result
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// Verify the operation was successful
	result := results[0]
	if !result.Success {
		t.Errorf("Quarantine should have succeeded, but got error: %v", result.Error)
	}

	// ASSERT: File should NO LONGER exist in source
	if _, err := os.Stat(testFilePath); !os.IsNotExist(err) {
		t.Error("File should have been MOVED (deleted) from source directory")
	}

	// ASSERT: File should NOW exist in target
	expectedTargetPath := filepath.Join(targetDir, testFileName)
	if _, err := os.Stat(expectedTargetPath); os.IsNotExist(err) {
		t.Error("File should exist in target directory after quarantine")
	}

	// Verify content was preserved
	movedContent, err := os.ReadFile(expectedTargetPath)
	if err != nil {
		t.Fatalf("Failed to read moved file: %v", err)
	}
	if string(movedContent) != string(testContent) {
		t.Error("File content should be preserved after move")
	}
}

func TestQuarantineFilesMultiple(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()

	// Create multiple test files
	testFiles := []string{"secret1.txt", "config.env", "keys.json"}
	var filePaths []string

	for _, name := range testFiles {
		path := filepath.Join(sourceDir, name)
		err := os.WriteFile(path, []byte("secret content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		filePaths = append(filePaths, path)
	}

	// Mock user input: "y" for all files
	oldInput := inputReader
	inputReader = strings.NewReader("y\ny\ny\n")
	defer func() { inputReader = oldInput }()

	// Perform the quarantine
	results, err := QuarantineFiles(filePaths, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles failed: %v", err)
	}

	// Verify all files were processed
	if len(results) != len(testFiles) {
		t.Fatalf("Expected %d results, got %d", len(testFiles), len(results))
	}

	// Verify all operations succeeded
	for _, result := range results {
		if !result.Success {
			t.Errorf("Quarantine of %s should have succeeded, got error: %v",
				result.OriginalPath, result.Error)
		}
	}

	// Verify all files moved from source
	for _, name := range testFiles {
		sourcePath := filepath.Join(sourceDir, name)
		if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
			t.Errorf("File %s should have been moved from source", name)
		}
	}

	// Verify all files exist in target
	for _, name := range testFiles {
		targetPath := filepath.Join(targetDir, name)
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			t.Errorf("File %s should exist in target", name)
		}
	}
}

func TestQuarantineFilesCollision(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()

	// Create a file in source
	testFileName := "secret.txt"
	sourcePath := filepath.Join(sourceDir, testFileName)
	err := os.WriteFile(sourcePath, []byte("new secret"), 0644)
	if err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Create a file with the SAME NAME in target (collision!)
	existingTargetPath := filepath.Join(targetDir, testFileName)
	err = os.WriteFile(existingTargetPath, []byte("existing secret"), 0644)
	if err != nil {
		t.Fatalf("Failed to create existing target file: %v", err)
	}

	// Mock user input: "y"
	oldInput := inputReader
	inputReader = strings.NewReader("y\n")
	defer func() { inputReader = oldInput }()

	// Perform the quarantine
	results, err := QuarantineFiles([]string{sourcePath}, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles failed: %v", err)
	}

	// Verify success
	if !results[0].Success {
		t.Fatalf("Quarantine should succeed even with collision, got: %v", results[0].Error)
	}

	// Verify original target file is UNTOUCHED
	existingContent, _ := os.ReadFile(existingTargetPath)
	if string(existingContent) != "existing secret" {
		t.Error("Existing file in target should NOT be overwritten")
	}

	// Verify new file was renamed (should have timestamp)
	newPath := results[0].NewPath
	if newPath == existingTargetPath {
		t.Error("New file should have a different name due to collision handling")
	}

	// Verify the new file exists
	if _, err := os.Stat(newPath); os.IsNotExist(err) {
		t.Errorf("Renamed file should exist at %s", newPath)
	}
}

func TestQuarantineCreatesTargetDir(t *testing.T) {
	sourceDir := t.TempDir()

	// Create a target path that DOESN'T exist yet
	targetDir := filepath.Join(t.TempDir(), "new", "nested", "vault")

	// Create test file
	sourcePath := filepath.Join(sourceDir, "secret.txt")
	err := os.WriteFile(sourcePath, []byte("secret"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Mock user input: "y"
	oldInput := inputReader
	inputReader = strings.NewReader("y\n")
	defer func() { inputReader = oldInput }()

	// Perform quarantine - should create the directory
	results, err := QuarantineFiles([]string{sourcePath}, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles should create target directory: %v", err)
	}

	if !results[0].Success {
		t.Errorf("Quarantine should succeed: %v", results[0].Error)
	}

	// Verify directory was created
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		t.Error("Target directory should have been created")
	}
}

func TestQuarantineDuplicatePaths(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()

	// Create a test file
	sourcePath := filepath.Join(sourceDir, "secret.txt")
	err := os.WriteFile(sourcePath, []byte("secret"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Mock user input: "y"
	oldInput := inputReader
	inputReader = strings.NewReader("y\n")
	defer func() { inputReader = oldInput }()

	// Pass the SAME path twice (simulating duplicate findings)
	results, err := QuarantineFiles([]string{sourcePath, sourcePath}, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles failed: %v", err)
	}

	// Should only process unique files
	if len(results) != 1 {
		t.Errorf("Should deduplicate paths, expected 1 result, got %d", len(results))
	}
}

func TestQuarantineNonExistentFile(t *testing.T) {
	targetDir := t.TempDir()

	// Mock user input: "y"
	oldInput := inputReader
	inputReader = strings.NewReader("y\n")
	defer func() { inputReader = oldInput }()

	// Try to quarantine a file that doesn't exist
	results, err := QuarantineFiles([]string{"/nonexistent/file.txt"}, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles shouldn't fail for non-existent files: %v", err)
	}

	// The individual operation should fail gracefully
	if len(results) != 1 {
		t.Fatal("Should have one result")
	}

	if results[0].Success {
		t.Error("Moving non-existent file should fail")
	}
}

func TestQuarantineFilesKeepOriginal(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()

	testFileName := "keep_me.txt"
	testFilePath := filepath.Join(sourceDir, testFileName)
	err := os.WriteFile(testFilePath, []byte("sensitive data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Mock user input: "n" to keep original
	oldInput := inputReader
	inputReader = strings.NewReader("n\n")
	defer func() { inputReader = oldInput }()

	results, err := QuarantineFiles([]string{testFilePath}, targetDir)
	if err != nil {
		t.Fatalf("QuarantineFiles failed: %v", err)
	}

	if !results[0].Success {
		t.Errorf("Quarantine should succeed even if original is kept")
	}

	// ASSERT: File should STILL exist in source
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Error("Original file should STILL exist in source because user chose 'n'")
	}

	// ASSERT: File should ALSO exist in target
	expectedTargetPath := filepath.Join(targetDir, testFileName)
	if _, err := os.Stat(expectedTargetPath); os.IsNotExist(err) {
		t.Error("File should have been copied to target")
	}
}
