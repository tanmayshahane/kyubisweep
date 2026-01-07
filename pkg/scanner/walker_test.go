package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// TEST: Walker
// Tests the concurrent directory walker with temporary directories
// =============================================================================

func TestWalkFindsFiles(t *testing.T) {
	// Create a complex directory structure using temp dirs
	rootDir := t.TempDir()

	// Create test files
	files := []string{
		"file1.txt",
		"file2.go",
		"config.json",
		"nested/deep/file3.py",
	}

	for _, f := range files {
		path := filepath.Join(rootDir, f)
		dir := filepath.Dir(path)

		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", path, err)
		}
	}

	// Start the walker with a channel
	filePaths := make(chan string, 100)

	go func() {
		Walk(rootDir, filePaths, false, DefaultTextExtensions)
		close(filePaths)
	}()

	// Collect all paths sent to the channel
	var foundPaths []string
	for path := range filePaths {
		foundPaths = append(foundPaths, path)
	}

	// Verify we found the expected number of files
	expectedCount := len(files)
	if len(foundPaths) != expectedCount {
		t.Errorf("Expected to find %d files, found %d", expectedCount, len(foundPaths))
	}
}

func TestWalkSkipsGitDirectory(t *testing.T) {
	rootDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(rootDir, "regular.txt")
	os.WriteFile(regularFile, []byte("content"), 0644)

	// Create a .git directory with files inside (should be skipped!)
	gitDir := filepath.Join(rootDir, ".git")
	os.MkdirAll(gitDir, 0755)
	gitFile := filepath.Join(gitDir, "config")
	os.WriteFile(gitFile, []byte("git config"), 0644)

	// Create a .git/objects subdirectory
	gitObjects := filepath.Join(gitDir, "objects", "ab")
	os.MkdirAll(gitObjects, 0755)
	os.WriteFile(filepath.Join(gitObjects, "123456"), []byte("object"), 0644)

	// Start the walker
	filePaths := make(chan string, 100)

	go func() {
		Walk(rootDir, filePaths, false, DefaultTextExtensions)
		close(filePaths)
	}()

	// Collect paths
	var foundPaths []string
	for path := range filePaths {
		foundPaths = append(foundPaths, path)
	}

	// Should find the regular file
	regularFound := false
	for _, p := range foundPaths {
		if filepath.Base(p) == "regular.txt" {
			regularFound = true
		}
	}
	if !regularFound {
		t.Error("Should find regular.txt")
	}

	// Should NOT find any .git files
	for _, p := range foundPaths {
		if filepath.Base(filepath.Dir(p)) == ".git" || filepath.Base(p) == ".git" {
			t.Errorf("Should NOT find files in .git directory, but found: %s", p)
		}
	}
}

func TestWalkSkipsNodeModules(t *testing.T) {
	rootDir := t.TempDir()

	// Create a regular file
	os.WriteFile(filepath.Join(rootDir, "index.js"), []byte("code"), 0644)

	// Create node_modules directory (should be skipped!)
	nodeModules := filepath.Join(rootDir, "node_modules", "some-package")
	os.MkdirAll(nodeModules, 0755)
	os.WriteFile(filepath.Join(nodeModules, "index.js"), []byte("module code"), 0644)

	// Start the walker
	filePaths := make(chan string, 100)

	go func() {
		Walk(rootDir, filePaths, false, DefaultTextExtensions)
		close(filePaths)
	}()

	// Collect paths
	var foundPaths []string
	for path := range filePaths {
		foundPaths = append(foundPaths, path)
	}

	// Should find only 1 file (the root index.js)
	if len(foundPaths) != 1 {
		t.Errorf("Expected 1 file (should skip node_modules), found %d", len(foundPaths))
	}

	// Verify no node_modules paths
	for _, p := range foundPaths {
		if filepath.Base(filepath.Dir(p)) == "node_modules" {
			t.Errorf("Should NOT find files in node_modules, but found: %s", p)
		}
	}
}

func TestWalkWithExtensionFilter(t *testing.T) {
	rootDir := t.TempDir()

	// Create files with different extensions
	os.WriteFile(filepath.Join(rootDir, "code.go"), []byte("go code"), 0644)
	os.WriteFile(filepath.Join(rootDir, "code.py"), []byte("python code"), 0644)
	os.WriteFile(filepath.Join(rootDir, "image.jpg"), []byte("fake image"), 0644)
	os.WriteFile(filepath.Join(rootDir, "binary.exe"), []byte("fake binary"), 0644)

	// Start the walker with default text extensions
	filePaths := make(chan string, 100)

	go func() {
		Walk(rootDir, filePaths, false, DefaultTextExtensions)
		close(filePaths)
	}()

	// Collect paths
	var foundPaths []string
	for path := range filePaths {
		foundPaths = append(foundPaths, path)
	}

	// Should find .go and .py files (text-based)
	foundGo := false
	foundPy := false
	foundJpg := false
	foundExe := false

	for _, p := range foundPaths {
		ext := filepath.Ext(p)
		switch ext {
		case ".go":
			foundGo = true
		case ".py":
			foundPy = true
		case ".jpg":
			foundJpg = true
		case ".exe":
			foundExe = true
		}
	}

	if !foundGo {
		t.Error("Should find .go files")
	}
	if !foundPy {
		t.Error("Should find .py files")
	}
	if foundJpg {
		t.Error("Should NOT find .jpg files (binary)")
	}
	if foundExe {
		t.Error("Should NOT find .exe files (binary)")
	}
}

func TestWalkEmptyDirectory(t *testing.T) {
	rootDir := t.TempDir()

	// Don't create any files - empty directory

	filePaths := make(chan string, 100)

	go func() {
		Walk(rootDir, filePaths, false, DefaultTextExtensions)
		close(filePaths)
	}()

	// Collect paths
	var foundPaths []string
	for path := range filePaths {
		foundPaths = append(foundPaths, path)
	}

	// Should find nothing
	if len(foundPaths) != 0 {
		t.Errorf("Expected 0 files in empty directory, found %d", len(foundPaths))
	}
}

func TestMergeExtensions(t *testing.T) {
	// Test merging custom extensions
	merged := MergeExtensions([]string{"dat", "log", "custom"})

	// Should contain default extensions
	if !merged[".go"] {
		t.Error("Merged map should contain default .go extension")
	}
	if !merged[".json"] {
		t.Error("Merged map should contain default .json extension")
	}

	// Should contain custom extensions
	if !merged[".dat"] {
		t.Error("Merged map should contain custom .dat extension")
	}
	if !merged[".log"] {
		t.Error("Merged map should contain custom .log extension")
	}
	if !merged[".custom"] {
		t.Error("Merged map should contain custom .custom extension")
	}
}

func TestMergeExtensionsNormalization(t *testing.T) {
	// Test that extensions are normalized (adding dot prefix)
	merged := MergeExtensions([]string{"txt", ".md", "JSON"})

	if !merged[".txt"] {
		t.Error("Should normalize 'txt' to '.txt'")
	}
	if !merged[".md"] {
		t.Error("Should keep '.md' as is")
	}
	if !merged[".json"] {
		t.Error("Should normalize 'JSON' to '.json' (lowercase)")
	}
}
