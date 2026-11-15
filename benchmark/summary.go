package benchmark

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

type Run struct {
	VulnAPIVersion string
	Date           time.Time
	Manifests      []*Manifest
	Results        []ScanResult
}

var labels = map[string]map[string]string{
	"en": {
		"intro":        "VulnAPI %s, %s.",
		"totals":       "**%d of %d known issues detected (%s)**, %d missed, %d known misses, %d not covered by a check yet, %d unexpected findings.",
		"header":       "| Target | Version | Issues | Detected | Missed | Known misses | Not covered | Unexpected findings |",
		"details":      "| Scan | Issue | Check | Result |",
		"unexpected":   "Unexpected findings, to review as false-positive candidates:",
		"error":        "error",
		"detected":     "detected",
		"missed":       "missed",
		"known miss":   "known miss",
		"now detected": "now detected",
		"not covered":  "not covered",
	},
	"fr": {
		"intro":        "VulnAPI %s, %s.",
		"totals":       "**%d problèmes connus détectés sur %d (%s)**, %d manqués, %d manques connus, %d pas encore couverts par une vérification, %d résultats inattendus.",
		"header":       "| Cible | Version | Problèmes | Détectés | Manqués | Manques connus | Non couverts | Résultats inattendus |",
		"details":      "| Scan | Problème | Vérification | Résultat |",
		"unexpected":   "Résultats inattendus, à examiner comme faux positifs potentiels :",
		"error":        "erreur",
		"detected":     "détecté",
		"missed":       "manqué",
		"known miss":   "manque connu",
		"now detected": "désormais détecté",
		"not covered":  "non couvert",
	},
}

func (r Run) totals() (detected, missed, knownMiss, notCovered, unexpected, total int) {
	for _, result := range r.Results {
		detected += result.Count(StatusDetected) + result.Count(StatusNowDetected)
		missed += result.Count(StatusMissed)
		knownMiss += result.Count(StatusKnownMiss)
		notCovered += result.Count(StatusNotCovered)
		unexpected += result.UnexpectedCount()
		total += len(result.Issues)
	}
	return
}

func percent(n, total int) string {
	if total == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", float64(n)*100/float64(total))
}

func (r Run) resultsOf(target string) []ScanResult {
	var results []ScanResult
	for _, result := range r.Results {
		if result.Target == target {
			results = append(results, result)
		}
	}
	return results
}

// Markdown renders the run as a Markdown document in lang ("en" or "fr").
func (r Run) Markdown(lang string) string {
	l, ok := labels[lang]
	if !ok {
		l = labels["en"]
	}
	var b strings.Builder
	detected, missed, knownMiss, notCovered, unexpected, total := r.totals()

	fmt.Fprintf(&b, l["intro"]+"\n\n", r.VulnAPIVersion, r.Date.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, l["totals"]+"\n\n", detected, total, percent(detected, total), missed, knownMiss, notCovered, unexpected)

	b.WriteString(l["header"] + "\n|---|---|---|---|---|---|---|---|\n")
	for _, m := range r.Manifests {
		var issues, det, mis, known, nc, unexp int
		for _, result := range r.resultsOf(m.Name) {
			issues += len(result.Issues)
			det += result.Count(StatusDetected) + result.Count(StatusNowDetected)
			mis += result.Count(StatusMissed)
			known += result.Count(StatusKnownMiss)
			nc += result.Count(StatusNotCovered)
			unexp += result.UnexpectedCount()
		}
		fmt.Fprintf(&b, "| [%s](%s) | `%s` | %d | %d | %d | %d | %d | %d |\n", m.Name, m.URL, m.Version, issues, det, mis, known, nc, unexp)
	}

	for _, m := range r.Manifests {
		fmt.Fprintf(&b, "\n### %s\n\n", m.Name)
		b.WriteString(l["details"] + "\n|---|---|---|---|\n")
		for _, result := range r.resultsOf(m.Name) {
			if result.Err != nil {
				fmt.Fprintf(&b, "| %s | | | %s: %s |\n", result.Scan, l["error"], strings.ReplaceAll(result.Err.Error(), "|", "\\|"))
				continue
			}
			for _, issue := range result.Issues {
				check := "-"
				if issue.Issue.Check != "" {
					check = "`" + issue.Issue.Check + "`"
				}
				status := l[string(issue.Status)]
				if link := issue.Issue.NotCovered + issue.Issue.KnownMiss; link != "" && issue.Status != StatusNowDetected {
					status = fmt.Sprintf("[%s](%s)", status, link)
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", result.Scan, issue.Issue.Title, check, status)
			}
		}
		var unexpectedLines []string
		for _, result := range r.resultsOf(m.Name) {
			for id, count := range result.Unexpected {
				unexpectedLines = append(unexpectedLines, fmt.Sprintf("- %s: `%s` (%d)", result.Scan, id, count))
			}
		}
		if len(unexpectedLines) > 0 {
			slices.Sort(unexpectedLines)
			b.WriteString("\n" + l["unexpected"] + "\n\n")
			b.WriteString(strings.Join(unexpectedLines, "\n"))
			b.WriteString("\n")
		}
	}
	return b.String()
}
