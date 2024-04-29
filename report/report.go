package report

import (
	"net/http"
	"time"
)

type VulnerabilityScanAttempt struct {
	Request  *http.Request  `json:"request"`
	Response *http.Response `json:"response"`

	Err error `json:"error"`
}

type ScanReport struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	Scans []*VulnerabilityScanAttempt `json:"scans"`
	Vulns []*VulnerabilityReport      `json:"vulnerabilities"`

	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

func NewScanReport(id string, name string) *ScanReport {
	return &ScanReport{
		ID:   id,
		Name: name,

		Scans: []*VulnerabilityScanAttempt{},
		Vulns: []*VulnerabilityReport{},

		StartTime: time.Now(),
	}
}

func (sc *ScanReport) Start() *ScanReport {
	sc.StartTime = time.Now()
	return sc
}

func (sc *ScanReport) End() *ScanReport {
	sc.EndTime = time.Now()
	return sc
}

func (sc *ScanReport) AddScanAttempt(a *VulnerabilityScanAttempt) *ScanReport {
	sc.Scans = append(sc.Scans, a)
	return sc
}

func (sc *ScanReport) GetScanAttempts() []*VulnerabilityScanAttempt {
	return sc.Scans
}

func (sc *ScanReport) AddVulnerabilityReport(vr *VulnerabilityReport) *ScanReport {
	sc.Vulns = append(sc.Vulns, vr)
	return sc
}

func (sc *ScanReport) GetVulnerabilityReports() []*VulnerabilityReport {
	return sc.Vulns
}

func (sc *ScanReport) HasVulnerabilityReport() bool {
	return len(sc.GetVulnerabilityReports()) > 0
}
