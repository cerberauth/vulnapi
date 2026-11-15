// Package benchmark measures how many known issues of public vulnerable
// APIs VulnAPI detects. Each target has an expected-findings manifest,
// benchmark/<target>/expected.yaml; the runner (go test -tags benchmark)
// scans the targets and compares the reports with the manifests.
package benchmark

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/cerberauth/vulnapi/scan"
	_ "github.com/cerberauth/vulnapi/scenario"
	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Version string `yaml:"version"`
	Scans   []Scan `yaml:"scans"`

	Dir string `yaml:"-"`
}

type Scan struct {
	Name   string   `yaml:"name"`
	Setup  []string `yaml:"setup,omitempty"`
	Token  string   `yaml:"token,omitempty"`
	Args   []string `yaml:"args"`
	Issues []Issue  `yaml:"issues"`
}

// Issue is a known issue of a target. Check is the check ID expected to
// report it; NotCovered links the issue tracking a check for it; KnownMiss
// links the issue tracking why its check does not report it yet.
type Issue struct {
	ID         string `yaml:"id"`
	Title      string `yaml:"title"`
	Check      string `yaml:"check,omitempty"`
	Operation  string `yaml:"operation,omitempty"`
	NotCovered string `yaml:"notCovered,omitempty"`
	KnownMiss  string `yaml:"knownMiss,omitempty"`
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m.Dir = filepath.Dir(path)
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

func LoadManifests(dir string) ([]*Manifest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "expected.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var manifests []*Manifest
	for _, path := range paths {
		m, err := LoadManifest(path)
		if err != nil {
			return nil, err
		}
		manifests = append(manifests, m)
	}
	return manifests, nil
}

func (m *Manifest) validate() error {
	if m.Name == "" || m.Version == "" {
		return errors.New("name and version are required")
	}
	if len(m.Scans) == 0 {
		return errors.New("at least one scan is required")
	}
	ids := map[string]bool{}
	for _, s := range m.Scans {
		if s.Name == "" || len(s.Args) == 0 {
			return errors.New("each scan needs a name and args")
		}
		for _, issue := range s.Issues {
			key := s.Name + "/" + issue.ID
			if issue.ID == "" || issue.Title == "" {
				return fmt.Errorf("scan %s: each issue needs an id and a title", s.Name)
			}
			if ids[key] {
				return fmt.Errorf("duplicate issue %s", key)
			}
			ids[key] = true
			if (issue.Check == "") == (issue.NotCovered == "") {
				return fmt.Errorf("issue %s: set exactly one of check or notCovered", key)
			}
			if issue.KnownMiss != "" && issue.Check == "" {
				return fmt.Errorf("issue %s: knownMiss needs a check", key)
			}
		}
	}
	return nil
}

type Finding struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	CVSS40Score float64           `json:"cvss40_score"`
	URL         string            `json:"url"`
	Extra       map[string]string `json:"extra"`
}

type Report struct {
	Findings []Finding `json:"findings"`
}

func ParseReport(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing report: %w", err)
	}
	return &r, nil
}

type Status string

const (
	StatusDetected    Status = "detected"
	StatusMissed      Status = "missed"
	StatusKnownMiss   Status = "known miss"
	StatusNowDetected Status = "now detected"
	StatusNotCovered  Status = "not covered"
)

type IssueResult struct {
	Issue  Issue
	Status Status
}

type ScanResult struct {
	Target     string
	Scan       string
	Issues     []IssueResult
	Unexpected map[string]int
	Err        error
}

func (i Issue) matches(f Finding) bool {
	if i.Check == "" || !scan.MatchesScanID(i.Check, f.ID) {
		return false
	}
	return i.Operation == "" || i.Operation == f.Extra["operation_id"]
}

func isActive(f Finding) bool {
	return f.Status == "" || f.Status == "active"
}

// Compare classifies every issue of s against the findings of report, and
// counts the findings with a CVSS score no issue expects, as false-positive
// candidates.
func Compare(target string, s Scan, report *Report) ScanResult {
	result := ScanResult{Target: target, Scan: s.Name, Unexpected: map[string]int{}}
	var findings []Finding
	for _, f := range report.Findings {
		if isActive(f) {
			findings = append(findings, f)
		}
	}
	for _, issue := range s.Issues {
		found := slices.ContainsFunc(findings, issue.matches)
		status := StatusNotCovered
		switch {
		case issue.Check == "":
		case found && issue.KnownMiss != "":
			status = StatusNowDetected
		case found:
			status = StatusDetected
		case issue.KnownMiss != "":
			status = StatusKnownMiss
		default:
			status = StatusMissed
		}
		result.Issues = append(result.Issues, IssueResult{Issue: issue, Status: status})
	}
	for _, f := range findings {
		if f.CVSS40Score > 0 && !slices.ContainsFunc(s.Issues, func(issue Issue) bool { return issue.matches(f) }) {
			result.Unexpected[f.ID]++
		}
	}
	return result
}

func (r ScanResult) Count(status Status) int {
	n := 0
	for _, issue := range r.Issues {
		if issue.Status == status {
			n++
		}
	}
	return n
}

func (r ScanResult) UnexpectedCount() int {
	n := 0
	for _, count := range r.Unexpected {
		n += count
	}
	return n
}

// Regressions lists the issues a check is expected to detect but did not.
func (r ScanResult) Regressions() []Issue {
	var issues []Issue
	for _, issue := range r.Issues {
		if issue.Status == StatusMissed {
			issues = append(issues, issue.Issue)
		}
	}
	return issues
}
