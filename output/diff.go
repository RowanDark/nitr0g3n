package output

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode"
)

// LoadRecords reads discovery records encoded as newline-delimited JSON or a JSON array.
func LoadRecords(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		b, err := reader.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, err
		}

		if unicode.IsSpace(rune(b[0])) {
			if _, err := reader.ReadByte(); err != nil {
				return nil, err
			}
			continue
		}

		if b[0] == '[' {
			var records []Record
			decoder := json.NewDecoder(reader)
			if err := decoder.Decode(&records); err != nil {
				return nil, err
			}
			return records, nil
		}

		break
	}

	decoder := json.NewDecoder(reader)
	records := make([]Record, 0)
	for {
		var record Record
		if err := decoder.Decode(&record); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}
