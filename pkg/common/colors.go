// Package common provides shared constants and utilities used across KyubiSweep.
package common

// ANSI Escape Codes for terminal colors
const (
	// Reset
	ColorReset = "\033[0m"

	// Text styles
	ColorBold = "\033[1m"
	ColorDim  = "\033[2m"

	// Foreground colors
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"

	// Background colors
	BgRed    = "\033[41m"
	BgGreen  = "\033[42m"
	BgYellow = "\033[43m"
	BgBlue   = "\033[44m"
)

// Colorize wraps text with ANSI color codes
func Colorize(text string, color string) string {
	return color + text + ColorReset
}

// Bold makes text bold
func Bold(text string) string {
	return ColorBold + text + ColorReset
}

// Red returns red-colored text
func Red(text string) string {
	return Colorize(text, ColorRed)
}

// Green returns green-colored text
func Green(text string) string {
	return Colorize(text, ColorGreen)
}

// Yellow returns yellow-colored text
func Yellow(text string) string {
	return Colorize(text, ColorYellow)
}

// Blue returns blue-colored text
func Blue(text string) string {
	return Colorize(text, ColorBlue)
}

// Cyan returns cyan-colored text
func Cyan(text string) string {
	return Colorize(text, ColorCyan)
}
