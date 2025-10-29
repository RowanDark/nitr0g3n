#!/bin/bash

echo "🔍 Checking nitr0g3n installation..."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed"
    echo "   Install from: https://golang.org/dl/"
    exit 1
fi
echo "✓ Go is installed: $(go version)"

# Check GOPATH
GOPATH=$(go env GOPATH)
echo "✓ GOPATH: $GOPATH"

# Check if binary exists
BINARY_PATH="$GOPATH/bin/nitr0g3n"
if [ -f "$BINARY_PATH" ]; then
    echo "✓ Binary found: $BINARY_PATH"
else
    echo "❌ Binary not found at: $BINARY_PATH"
    echo "   Run: go install github.com/RowanDark/nitr0g3n@latest"
    exit 1
fi

# Check if binary is in PATH
if command -v nitr0g3n &> /dev/null; then
    echo "✓ nitr0g3n is in PATH"
    echo "✓ Version: $(nitr0g3n --version 2>&1 | head -n1)"
else
    echo "⚠️  nitr0g3n is NOT in PATH"
    echo ""
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"$PATH:$GOPATH/bin\""
    echo ""
    echo "Then run: source ~/.bashrc  # or source ~/.zshrc"
    exit 1
fi

echo ""
echo "✅ Everything looks good! You can now use nitr0g3n"
