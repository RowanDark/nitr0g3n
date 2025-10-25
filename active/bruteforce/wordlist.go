package bruteforce

import (
	"bufio"
	"bytes"
	"embed"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

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

	words, err := readWordlist(file, 0)
	if err != nil {
		return nil
	}
	return words
}

// LoadWordlist reads a wordlist from the provided file path.
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	size := info.Size()
	if size > largeWordlistThreshold && info.Mode().IsRegular() && size <= int64(^uint(0)>>1) {
		data, err := unix.Mmap(int(file.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_PRIVATE)
		if err == nil {
			words, readErr := readWordlist(bytes.NewReader(data), int(size))
			_ = unix.Munmap(data)
			if readErr != nil {
				return nil, readErr
			}
			return words, nil
		}
		// fall back to streaming reader if mmap fails
	}

	hint := 0
	if size <= int64(^uint(0)>>1) {
		hint = int(size)
	}
	words, err := readWordlist(file, hint)
	if err != nil {
		return nil, err
	}
	return words, nil
}

const (
	scannerBufferSize      = 64 * 1024
	maxWordSize            = 4 * 1024 * 1024
	largeWordlistThreshold = 10 * 1024 * 1024
)

func readWordlist(r io.Reader, sizeHint int) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, scannerBufferSize), maxWordSize)

	capacity := 256
	if sizeHint <= 0 {
		if statter, ok := r.(interface{ Stat() (fs.FileInfo, error) }); ok {
			if info, err := statter.Stat(); err == nil {
				sizeHint = int(info.Size())
			}
		}
	}
	if sizeHint > 0 {
		estimate := sizeHint / 8
		if estimate > capacity {
			capacity = estimate
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

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.SliceStable(words, func(i, j int) bool {
		if len(words[i]) == len(words[j]) {
			return words[i] < words[j]
		}
		return len(words[i]) < len(words[j])
	})

	return words, nil
}
