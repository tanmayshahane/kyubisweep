# 🦊 KyubiSweep

> **Hunt exposed secrets with the cunning of a fox!**

A lightweight, cross-platform CLI tool that scans your filesystem to detect exposed secrets, API keys, and tokens. Built with Go for maximum performance and zero dependencies.

---

## ✨ Features

- 🔍 **30+ Secret Patterns** - Detects AWS, Stripe, GitHub, Google, Slack, database credentials, and more
- 🧮 **Shannon Entropy Analysis** - Catches random high-entropy strings that regex might miss
- ⚡ **Concurrent Scanning** - Uses Go's goroutines for blazing-fast parallel processing
- � **Security Hygiene Scorecard** - Beautiful terminal output with color-coded risk levels
- �📦 **Zero Dependencies** - Single static binary, just download and run
- 🖥️ **Cross-Platform** - Works on macOS (Intel + Apple Silicon), Linux, and Windows
- 🎯 **Smart Filtering** - Scans only text-based files by default, skips binaries
- 🔒 **Quarantine Mode** - Move sensitive files to a secure vault location

---

## 🚀 Quick Start

### Option 1: Download Pre-built Binary

```bash
# macOS Apple Silicon (M1/M2/M3)
curl -L -o kyubisweep https://github.com/tanmayshahane/kyubisweep/releases/latest/kyubisweep-darwin-arm64
chmod +x kyubisweep

# Run it!
./kyubisweep --path /path/to/your/project
```

### Option 2: Build from Source

```bash
# Ensure Go 1.21+ is installed
go version

# Clone and build
git clone https://github.com/tanmayshahane/kyubisweep.git
cd kyubisweep
go build -o kyubisweep ./cmd/sweep/main.go

# Run it!
./kyubisweep --path .
```

---

## 📖 Usage

```
USAGE:
  kyubisweep [OPTIONS]

OPTIONS:
  --path <directory>   Path to scan (default: current directory)
  --verbose            Enable detailed output
  --all                Show all severity levels (default: HIGH only)
  --all-files          Scan all files, not just text-based files
  --ext <extensions>   Additional extensions to scan (comma-separated)
  --json               Output report as JSON file
  --no-report          Don't save report file
  --quiet              Minimal output, just summary
  --move-to <path>     Move files with secrets to quarantine directory
  --help               Show this help message

EXAMPLES:
  kyubisweep --path ./my-project
  kyubisweep --path . --all                    # Show all severities
  kyubisweep --path . --ext log,dat            # Add custom extensions
  kyubisweep --path . --move-to ./vault        # Quarantine sensitive files
  kyubisweep --path . --json                   # Export as JSON
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║     🛡️  KYUBISWEEP SECURITY HYGIENE SCORECARD                            ║
╚══════════════════════════════════════════════════════════════════════════╝

  🚨 CRITICAL ISSUES FOUND

  📊 RISK BREAKDOWN
  ─────────────────────────────────────────
  🚨 CRITICAL   9 ████████████████░░░░
  🔴 HIGH       2 ███░░░░░░░░░░░░░░░░░
  🟡 MEDIUM     0 ░░░░░░░░░░░░░░░░░░░░
  🔵 LOW        0 ░░░░░░░░░░░░░░░░░░░░

  🔍 FINDINGS DETAIL
  ─────────────────────────────────────────
  RISK        TYPE                        LOCATION
  [CRITICAL]  AWS Access Key ID           ~/project/.env:5
  [CRITICAL]  PostgreSQL Connection       ~/project/config.yaml:12
  [HIGH]      Stripe Secret Key           ~/project/payment.js:42

  📁 Scanned: ~/my-project
  📄 Files analyzed: 2.9K
  ⏱️  Duration: 1.2s
```

---

## 🔐 What It Detects

| Category | Examples |
|----------|----------|
| **Cloud Credentials** | AWS Access Keys, Google API Keys, Azure tokens |
| **Payment Systems** | Stripe API keys (live & test) |
| **Developer Tools** | GitHub PATs, NPM tokens, Heroku API keys |
| **Communication** | Slack tokens, Discord bot tokens, Twilio keys |
| **Databases** | PostgreSQL, MongoDB, MySQL connection strings |
| **Cryptographic** | RSA/SSH/PGP private keys |
| **Generic** | Passwords, API keys, Bearer tokens |

---

## 🏗️ Project Structure

```
kyubisweep/
├── cmd/
│   └── sweep/
│       └── main.go           # CLI entry point + worker pool
├── pkg/
│   ├── analyzer/
│   │   └── analyzer.go       # Entropy + regex detection
│   ├── scanner/
│   │   └── walker.go         # Concurrent directory walker
│   ├── reporter/
│   │   └── reporter.go       # Security Scorecard output
│   ├── quarantine/
│   │   └── manager.go        # Secure file relocation
│   └── common/
│       └── colors.go         # Shared ANSI color utilities
├── micro-tutorials/          # Go learning resources
├── reports/                  # Generated scan reports
├── build/                    # Cross-compiled binaries
├── go.mod                    # Go module definition
├── build.sh                  # Cross-platform build script
└── README.md
```

---

## 🛠️ Building for All Platforms

```bash
# Make the build script executable
chmod +x build.sh

# Build for all platforms
./build.sh

# Outputs:
# build/kyubisweep-darwin-arm64   (macOS Apple Silicon)
# build/kyubisweep-darwin-amd64   (macOS Intel)
# build/kyubisweep-linux-amd64    (Linux 64-bit)
# build/kyubisweep-linux-arm64    (Linux ARM)
# build/kyubisweep-windows-amd64.exe (Windows 64-bit)
```

---

## � Quarantine Mode

Found secrets you need to secure immediately? Use `--move-to` to relocate files:

```bash
./kyubisweep --path . --move-to ./secure_vault
```

**Safety features:**
- ⚠️ Bold red warning before any files are moved
- 🔐 Requires typing "yes" to confirm
- 📂 Creates vault directory with secure permissions (0700)
- 🔄 Handles cross-filesystem moves automatically
- 📛 Prevents overwrites with timestamp-based naming

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

MIT License - feel free to use this in your own projects!

---

<p align="center">
  <em>Made with 🦊 by developers who accidentally committed their API keys one too many times.</em>
</p>
