# Installation Guide

## Quick Install
```bash
go install github.com/RowanDark/nitr0g3n@latest
```

## Troubleshooting Common Issues

### "command not found" after installation

**Problem:** You installed nitr0g3n successfully but get `command not found` when trying to run it.

**Cause:** Go's bin directory (`$GOPATH/bin`) is not in your system PATH.

**Solution:**

1. **Find where Go installed the binary:**
```bash
   ls $(go env GOPATH)/bin/nitr0g3n
```
   If this shows the file, the installation worked!

2. **Add Go's bin directory to your PATH:**
   
   For **bash** users (most Linux, older macOS):
```bash
   echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
   source ~/.bashrc
```
   
   For **zsh** users (modern macOS, some Linux):
```bash
   echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
   source ~/.zshrc
```
   
   For **fish** users:
```bash
   set -Ua fish_user_paths (go env GOPATH)/bin
```

3. **Verify it works:**
```bash
   nitr0g3n --version
```

4. **Temporary workaround** (if you don't want to modify PATH):
```bash
   $(go env GOPATH)/bin/nitr0g3n --domain example.com --mode passive
```

### Can't find Go or go command

**Problem:** `go: command not found`

**Solution:** Install Go from https://golang.org/dl/ or via your package manager:
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install golang-go

# macOS with Homebrew
brew install go

# Arch Linux
sudo pacman -S go

# Fedora/RHEL
sudo dnf install golang
```

After installing Go, restart your terminal and try again.

### Permission denied errors

**Problem:** Can't write to installation directory.

**Solution:** Make sure `$GOPATH/bin` exists and is writable:
```bash
mkdir -p $(go env GOPATH)/bin
chmod +x $(go env GOPATH)/bin
```

### Module download errors

**Problem:** `go: github.com/RowanDark/nitr0g3n@latest: reading https://...`

**Solutions:**
- Check your internet connection
- Verify you can access GitHub: `curl https://github.com`
- If behind a proxy, configure Go: `go env -w GOPROXY=https://proxy.golang.org,direct`
- Clear Go's module cache: `go clean -modcache`

### Old version won't update

**Problem:** `go install` completed but `--version` shows an old version.

**Solution:**
```bash
# Clear the module cache
go clean -modcache

# Remove old binary
rm $(go env GOPATH)/bin/nitr0g3n

# Reinstall
go install github.com/RowanDark/nitr0g3n@latest

# Verify
nitr0g3n --version
```

## Alternative Installation Methods

### Manual Build from Source
```bash
git clone https://github.com/RowanDark/nitr0g3n.git
cd nitr0g3n
go build -o nitr0g3n
sudo mv nitr0g3n /usr/local/bin/
```

### Install Specific Version
```bash
# Install a specific commit
go install github.com/RowanDark/nitr0g3n@commit-hash

# Install a specific tag (once you start using releases)
go install github.com/RowanDark/nitr0g3n@v1.0.0
```

### Docker Installation (Coming Soon)
```bash
docker pull ghcr.io/rowandark/nitr0g3n:latest
docker run --rm nitr0g3n --domain example.com --mode passive
```

## Platform-Specific Notes

### Linux
- Default GOPATH: `~/go`
- Binary location: `~/go/bin/nitr0g3n`
- Recommended: Add to PATH in `~/.bashrc` or `~/.zshrc`

### macOS
- Default GOPATH: `~/go`
- Binary location: `~/go/bin/nitr0g3n`
- Recommended: Add to PATH in `~/.zshrc` (macOS Catalina+)

### Windows
- Default GOPATH: `%USERPROFILE%\go`
- Binary location: `%USERPROFILE%\go\bin\nitr0g3n.exe`
- Add to PATH via System Properties → Environment Variables

## Verifying Installation

After installation, verify everything works:
```bash
# Check version
nitr0g3n --version

# Check help
nitr0g3n --help

# Quick test (passive scan)
nitr0g3n --domain example.com --mode passive --silent

# You should see JSON output with discovered subdomains
```

## Getting Help

If you're still having issues:

1. Check existing issues: https://github.com/RowanDark/nitr0g3n/issues
2. Open a new issue with:
   - Your OS and version
   - Go version: `go version`
   - GOPATH: `go env GOPATH`
   - Installation command used
   - Complete error message
