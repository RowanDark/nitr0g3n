package output

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

// LoadRecords reads newline-delimited JSON records from the provided path.
func LoadRecords(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
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
