// Package analyzer provides secret detection using regex patterns and Shannon entropy.
package analyzer

import (
	"bufio"
	"math"
	"os"
	"regexp"
	"strings"
)

// Finding represents a discovered secret or suspicious content.
type Finding struct {
	FilePath   string
	LineNumber int
	Type       string
	Match      string
	Severity   string
	Entropy    float64
}

// SecretPattern defines a regex pattern for a known secret type.
type SecretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}

// Secret patterns for known API keys and tokens
var secretPatterns = []SecretPattern{
	// AWS
	{Name: "AWS Access Key ID", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: "HIGH"},
	{Name: "AWS Secret Access Key", Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`), Severity: "HIGH"},

	// Stripe
	{Name: "Stripe Secret Key", Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), Severity: "HIGH"},
	{Name: "Stripe Publishable Key", Pattern: regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), Severity: "MEDIUM"},

	// GitHub
	{Name: "GitHub Personal Access Token", Pattern: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), Severity: "HIGH"},
	{Name: "GitHub OAuth Access Token", Pattern: regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`), Severity: "HIGH"},
	{Name: "GitHub App Token", Pattern: regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`), Severity: "HIGH"},

	// Google
	{Name: "Google API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Severity: "HIGH"},
	{Name: "Google OAuth Token", Pattern: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`), Severity: "HIGH"},

	// Slack
	{Name: "Slack Bot Token", Pattern: regexp.MustCompile(`xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`), Severity: "HIGH"},
	{Name: "Slack User Token", Pattern: regexp.MustCompile(`xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`), Severity: "HIGH"},
	{Name: "Slack Webhook URL", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}`), Severity: "HIGH"},

	// Database Connection Strings
	{Name: "PostgreSQL Connection String", Pattern: regexp.MustCompile(`postgres(ql)?://[^:\s]+:[^@\s]+@[^\s]+`), Severity: "HIGH"},
	{Name: "MongoDB Connection String", Pattern: regexp.MustCompile(`mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s]+`), Severity: "HIGH"},
	{Name: "MySQL Connection String", Pattern: regexp.MustCompile(`mysql://[^:\s]+:[^@\s]+@[^\s]+`), Severity: "HIGH"},

	// Private Keys
	{Name: "RSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), Severity: "HIGH"},
	{Name: "SSH Private Key", Pattern: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), Severity: "HIGH"},
	{Name: "PGP Private Key", Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), Severity: "HIGH"},

	// Generic Secrets
	{Name: "Generic API Key", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"][0-9a-zA-Z]{16,}['"]`), Severity: "MEDIUM"},
	{Name: "Generic Secret", Pattern: regexp.MustCompile(`(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"][^'"]{8,}['"]`), Severity: "MEDIUM"},
	{Name: "Bearer Token", Pattern: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_\.]+`), Severity: "MEDIUM"},

	// Other Services
	{Name: "Twilio API Key", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Severity: "HIGH"},
	{Name: "SendGrid API Key", Pattern: regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`), Severity: "HIGH"},
	{Name: "Mailchimp API Key", Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Severity: "HIGH"},
	{Name: "NPM Token", Pattern: regexp.MustCompile(`npm_[0-9a-zA-Z]{36}`), Severity: "HIGH"},
	{Name: "Discord Bot Token", Pattern: regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`), Severity: "HIGH"},
	{Name: "Heroku API Key", Pattern: regexp.MustCompile(`(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]`), Severity: "HIGH"},
}

// Entropy thresholds
const (
	EntropyThreshold = 4.5
	MinEntropyLength = 20
	MaxEntropyLength = 100
)

// CalculateEntropy computes the Shannon entropy of a string.
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCount := make(map[rune]int)
	for _, char := range s {
		charCount[char]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range charCount {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// AnalyzeFile scans a file for secrets using regex and entropy analysis.
func AnalyzeFile(filePath string) []Finding {
	findings := make([]Finding, 0)

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Check regex patterns
		for _, pattern := range secretPatterns {
			matches := pattern.Pattern.FindAllString(line, -1)
			for _, match := range matches {
				findings = append(findings, Finding{
					FilePath:   filePath,
					LineNumber: lineNumber,
					Type:       pattern.Name,
					Match:      match,
					Severity:   pattern.Severity,
					Entropy:    0,
				})
			}
		}

		// Check for high entropy strings
		entropyFindings := findHighEntropyStrings(line, lineNumber, filePath)
		findings = append(findings, entropyFindings...)
	}

	return findings
}

func findHighEntropyStrings(line string, lineNumber int, filePath string) []Finding {
	findings := make([]Finding, 0)

	quotedStringPattern := regexp.MustCompile(`['"]([^'"]{20,100})['"]`)
	matches := quotedStringPattern.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		content := match[1]

		if looksLikeFalsePositive(content) {
			continue
		}

		entropy := CalculateEntropy(content)

		if entropy >= EntropyThreshold {
			findings = append(findings, Finding{
				FilePath:   filePath,
				LineNumber: lineNumber,
				Type:       "High Entropy String",
				Match:      content,
				Severity:   "MEDIUM",
				Entropy:    entropy,
			})
		}
	}

	return findings
}

func looksLikeFalsePositive(s string) bool {
	lowered := strings.ToLower(s)

	if strings.HasPrefix(lowered, "http://") || strings.HasPrefix(lowered, "https://") {
		return true
	}

	if strings.Contains(s, "/") && (strings.HasPrefix(s, "/") || strings.Contains(s, "./")) {
		return true
	}

	falsePositiveIndicators := []string{
		"example", "sample", "placeholder", "your_", "your-",
		"xxx", "abc", "test", "demo", "localhost", "undefined", "null",
	}

	for _, indicator := range falsePositiveIndicators {
		if strings.Contains(lowered, indicator) {
			return true
		}
	}

	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if uuidPattern.MatchString(lowered) {
		return true
	}

	return false
}
