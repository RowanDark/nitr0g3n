package bruteforce

import (
	"bufio"
	"embed"
	"io"
	"os"
	"strings"
)

//go:embed wordlists/top-1000.txt
var defaultWordlistFS embed.FS

// DefaultWordlist returns the embedded default bruteforce wordlist.
func DefaultWordlist() []string {
	file, err := defaultWordlistFS.Open("wordlists/top-1000.txt")
	if err != nil {
		return nil
	}
	defer file.Close()

	return readWordlist(file)
}

// LoadWordlist reads a wordlist from the provided file path.
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return readWordlist(file), nil
}

func readWordlist(r io.Reader) []string {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	var words []string
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		words = append(words, word)
	}

	return words
}
