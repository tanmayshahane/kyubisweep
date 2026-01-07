package analyzer

import (
	"math"
	"testing"
)

// =============================================================================
// TEST: CalculateEntropy
// Uses Table-Driven Tests - the idiomatic Go testing patterns
// =============================================================================

func TestCalculateEntropy(t *testing.T) {
	// Table-driven tests: define inputs and expected outputs as a slice of structs
	tests := []struct {
		name     string  // Descriptive name for the test case
		input    string  // Input string to test
		minValue float64 // Minimum expected entropy
		maxValue float64 // Maximum expected entropy
	}{
		{
			name:     "empty string",
			input:    "",
			minValue: 0,
			maxValue: 0,
		},
		{
			name:     "single character repeated",
			input:    "aaaaaaaaaa",
			minValue: 0,
			maxValue: 0.1, // Very low entropy
		},
		{
			name:     "two characters alternating",
			input:    "abababababab",
			minValue: 0.9,
			maxValue: 1.1, // log2(2) = 1
		},
		{
			name:     "four distinct characters",
			input:    "abcdabcdabcd",
			minValue: 1.9,
			maxValue: 2.1, // log2(4) = 2
		},
		{
			name:     "high entropy random string",
			input:    "8jKz9Lk2mNpQrStUvWxYz",
			minValue: 4.0,
			maxValue: 5.0,
		},
		{
			name:     "real-looking API key",
			input:    "ghp_abcdefghij1234567890xyzABCDEFGH",
			minValue: 3.5,
			maxValue: 5.5,
		},
	}

	// Iterate over all test cases using t.Run for subtests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateEntropy(tc.input)

			if got < tc.minValue || got > tc.maxValue {
				t.Errorf("CalculateEntropy(%q) = %v, want between %v and %v",
					tc.input, got, tc.minValue, tc.maxValue)
			}
		})
	}
}

// Test entropy for specific known values
func TestCalculateEntropyKnownValues(t *testing.T) {
	// Empty string should have 0 entropy
	if entropy := CalculateEntropy(""); entropy != 0 {
		t.Errorf("CalculateEntropy(\"\") = %v, want 0", entropy)
	}

	// Single char repeated has 0 entropy
	if entropy := CalculateEntropy("aaaa"); entropy != 0 {
		t.Errorf("CalculateEntropy(\"aaaa\") = %v, want 0", entropy)
	}

	// Two equal probability chars should have entropy = 1
	entropy := CalculateEntropy("ab")
	if math.Abs(entropy-1.0) > 0.01 {
		t.Errorf("CalculateEntropy(\"ab\") = %v, want 1.0", entropy)
	}
}

// =============================================================================
// TEST: Regex Pattern Matching
// Tests that our secret patterns correctly identify known secrets
// =============================================================================

func TestSecretPatternMatching(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		patternName string // Optional: which pattern should match
	}{
		// AWS Access Key ID tests
		{
			name:        "valid AWS Access Key ID",
			input:       `AWS_KEY="AKIAIOSFODNN7EXAMPLE"`,
			shouldMatch: true,
			patternName: "AWS Access Key ID",
		},
		{
			name:        "AWS key in config file",
			input:       `access_key_id = AKIAI44QH8DHBEXAMPLE`,
			shouldMatch: true,
			patternName: "AWS Access Key ID",
		},
		{
			name:        "invalid AWS key (too short)",
			input:       `key = AKIA1234`,
			shouldMatch: false,
		},

		// Note: Stripe tests removed to avoid GitHub secret scanning triggers
		// The analyzer.go patterns do cover sk_live_ and pk_live_ patterns

		// GitHub Token tests
		{
			name:        "valid GitHub PAT",
			input:       `token = ghp_1234567890abcdefghijklmnopqrstuvwxyz`,
			shouldMatch: true,
			patternName: "GitHub Personal Access Token",
		},

		// Database connection strings
		{
			name:        "PostgreSQL connection string",
			input:       `DATABASE_URL=postgres://user:password123@localhost:5432/mydb`,
			shouldMatch: true,
			patternName: "PostgreSQL Connection String",
		},
		{
			name:        "MongoDB connection string",
			input:       `MONGO_URI="mongodb://testuser:testpass@cluster.mongodb.net/db"`,
			shouldMatch: true,
			patternName: "MongoDB Connection String",
		},

		// Private keys
		{
			name:        "RSA private key header",
			input:       `-----BEGIN RSA PRIVATE KEY-----`,
			shouldMatch: true,
			patternName: "RSA Private Key",
		},
		{
			name:        "SSH private key header",
			input:       `-----BEGIN OPENSSH PRIVATE KEY-----`,
			shouldMatch: true,
			patternName: "SSH Private Key",
		},

		// Negative tests (should NOT match)
		{
			name:        "normal text",
			input:       `This is just a normal comment about the API.`,
			shouldMatch: false,
		},
		{
			name:        "placeholder text",
			input:       `AWS_KEY=your_key_here`,
			shouldMatch: false,
		},
		{
			name:        "example in documentation",
			input:       `# Example: AKIA + 16 alphanumeric characters`,
			shouldMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			matchedPattern := ""

			// Check all patterns
			for _, pattern := range secretPatterns {
				if pattern.Pattern.MatchString(tc.input) {
					matched = true
					matchedPattern = pattern.Name
					break
				}
			}

			if matched != tc.shouldMatch {
				if tc.shouldMatch {
					t.Errorf("Expected pattern to match %q (looking for %s), but no pattern matched",
						tc.input, tc.patternName)
				} else {
					t.Errorf("Expected NO pattern to match %q, but %q matched",
						tc.input, matchedPattern)
				}
			}
		})
	}
}

// =============================================================================
// TEST: False Positive Filtering
// Tests that common false positives are correctly filtered out
// =============================================================================

func TestLooksLikeFalsePositive(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		isFalsePositive bool
	}{
		{
			name:            "URL",
			input:           "https://example.com/api/v1/users",
			isFalsePositive: true,
		},
		{
			name:            "file path",
			input:           "/usr/local/bin/something",
			isFalsePositive: true,
		},
		{
			name:            "placeholder with your_",
			input:           "your_api_key_here_replace_me",
			isFalsePositive: true,
		},
		{
			name:            "example text",
			input:           "example_key_1234567890abcdef",
			isFalsePositive: true,
		},
		{
			name:            "test placeholder",
			input:           "test_api_key_placeholder_value",
			isFalsePositive: true,
		},
		{
			name:            "UUID format",
			input:           "550e8400-e29b-41d4-a716-446655440000",
			isFalsePositive: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := looksLikeFalsePositive(tc.input)
			if got != tc.isFalsePositive {
				t.Errorf("looksLikeFalsePositive(%q) = %v, want %v",
					tc.input, got, tc.isFalsePositive)
			}
		})
	}
}
