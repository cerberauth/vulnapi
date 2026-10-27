// Package seclist loads the path lists embedded in vulnapi for discovery
// scans.
package seclist

import (
	"bufio"
	"embed"
	"fmt"
	"strings"
)

//go:embed lists/*.txt
var embeddedLists embed.FS

type SecList struct {
	Name  string
	Items []string
}

func NewSecList(name string) *SecList {
	return &SecList{
		Name:  name,
		Items: []string{},
	}
}

// NewSecListFromEmbeddedFile loads the embedded list lists/<filename>, one
// item per non-empty line.
func NewSecListFromEmbeddedFile(name, filename string) (*SecList, error) {
	file, err := embeddedLists.Open("lists/" + filename)
	if err != nil {
		return nil, fmt.Errorf("unknown sec list %q: %w", filename, err)
	}
	defer file.Close()

	s := NewSecList(name)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			s.Items = append(s.Items, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return s, nil
}
