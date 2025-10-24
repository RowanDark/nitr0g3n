package bruteforce

import (
	"bufio"
	"embed"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/yourusername/nitr0g3n/internal/intern"
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

	capacity := 256
	if statter, ok := r.(interface{ Stat() (fs.FileInfo, error) }); ok {
		if info, err := statter.Stat(); err == nil {
			if size := info.Size(); size > 0 {
				estimate := int(size / 8)
				if estimate > capacity {
					capacity = estimate
				}
			}
		}
	}

	words := make([]string, 0, capacity)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		words = append(words, intern.Intern(word))
	}

	return words
}
