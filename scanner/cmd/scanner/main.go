// Command scanner reads text on stdin and prints PII findings as JSON lines.
//
// Today this is a CLI so the detectors can be exercised in isolation. The roadmap
// turns it into a worker that consumes "file uploaded" events, streams the object
// from storage, and reports a verdict back to the API.
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/detect"
)

type result struct {
	Kind  detect.Kind `json:"kind"`
	Start int         `json:"start"`
	End   int         `json:"end"`
}

func main() {
	data, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, f := range detect.Scan(string(data)) {
		// Positions only: matched values never leave the scanner.
		if err := enc.Encode(result{f.Kind, f.Start, f.End}); err != nil {
			log.Fatal(err)
		}
	}
}
