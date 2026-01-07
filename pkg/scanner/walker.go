// Package scanner provides directory traversal for finding files to scan.
package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Directories to skip during scanning
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".idea":        true,
	".vscode":      true,
	"__pycache__":  true,
	".next":        true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".gradle":      true,
	".npm":         true,
	".cache":       true,
}

// DefaultTextExtensions are file extensions for text-based files that commonly contain secrets
var DefaultTextExtensions = map[string]bool{
	// Configuration files
	".env": true, ".env.local": true, ".env.development": true, ".env.production": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".xml": true,
	".ini": true, ".cfg": true, ".conf": true, ".config": true, ".properties": true,

	// Source code
	".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".java": true, ".kt": true, ".scala": true, ".rb": true, ".php": true,
	".cs": true, ".cpp": true, ".c": true, ".h": true, ".hpp": true,
	".rs": true, ".swift": true, ".m": true, ".mm": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true,
	".ps1": true, ".bat": true, ".cmd": true,

	// Web
	".html": true, ".htm": true, ".css": true, ".scss": true, ".less": true,
	".vue": true, ".svelte": true,

	// Documentation
	".md": true, ".markdown": true, ".txt": true, ".rst": true,

	// Data
	".sql": true, ".graphql": true, ".gql": true,
	".csv": true, ".tsv": true,

	// DevOps / IaC
	".tf": true, ".tfvars": true, ".hcl": true,
	".dockerfile": true, ".dockerignore": true,
	".gitignore": true, ".gitattributes": true,
	".editorconfig": true, ".prettierrc": true, ".eslintrc": true,

	// Keys and certs (important to scan!)
	".pem": true, ".key": true, ".crt": true, ".cer": true,
	".pub": true, ".ppk": true,

	// Notebooks (as text)
	".ipynb": true, ".rmd": true,

	// Other
	".log": true, ".htaccess": true, ".htpasswd": true,
	".gradle": true, ".plist": true, ".xcconfig": true,
}

// maxFileSize is the maximum file size to scan (5 MB - reduced for text files)
const maxFileSize = 5 * 1024 * 1024

// Walk traverses the directory tree and sends file paths to the channel.
// It uses the allowedExtensions map to filter files. Pass nil to use defaults.
func Walk(rootPath string, filePaths chan<- string, verbose bool, allowedExtensions map[string]bool) {
	// Use default extensions if none provided
	if allowedExtensions == nil {
		allowedExtensions = DefaultTextExtensions
	}

	_ = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return nil
		}

		// Skip unwanted directories
		if d.IsDir() {
			dirName := d.Name()
			if skipDirs[dirName] {
				return fs.SkipDir
			}
			if strings.HasPrefix(dirName, ".") && dirName != "." {
				return fs.SkipDir
			}
			return nil
		}

		// Filter out unwanted files
		fileName := d.Name()
		if strings.HasPrefix(fileName, ".") && fileName != ".env" && !strings.HasPrefix(fileName, ".env.") {
			// Skip hidden files except .env files
			if !allowedExtensions[fileName] {
				return nil
			}
		}

		// Check extension - only scan allowed text-based files
		ext := strings.ToLower(filepath.Ext(fileName))
		if ext == "" {
			// Check if filename itself is in allowed list (e.g., "Dockerfile", ".gitignore")
			if !allowedExtensions[strings.ToLower(fileName)] {
				return nil
			}
		} else if !allowedExtensions[ext] {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxFileSize || info.Size() == 0 {
			return nil
		}

		// Send file path to channel for processing
		filePaths <- path
		return nil
	})
}

// MergeExtensions combines default extensions with additional ones
func MergeExtensions(additional []string) map[string]bool {
	merged := make(map[string]bool)

	// Copy defaults
	for ext, val := range DefaultTextExtensions {
		merged[ext] = val
	}

	// Add additional extensions
	for _, ext := range additional {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		merged[strings.ToLower(ext)] = true
	}

	return merged
}

// AllExtensions returns a map that allows all file extensions (for --all-files mode)
func AllExtensions() map[string]bool {
	return nil // nil signals to use permissive mode
}

// IsTextFile checks if a file is likely a text file (not binary).
func IsTextFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil || n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			return false
		}
	}
	return true
}
