package report

import (
	"net/http"
	"time"
)

type VulnerabilityScanAttempt struct {
	Request  *http.Request
	Response *http.Response

	Err error
}

type ScanReport struct {
	scans []*VulnerabilityScanAttempt
	vulns []*VulnerabilityReport

	startTime time.Time
	endTime   time.Time
}

func NewScanReport() *ScanReport {
	return &ScanReport{
		startTime: time.Now(),
	}
}

func (sc *ScanReport) Start() *ScanReport {
	sc.startTime = time.Now()
	return sc
}

func (sc *ScanReport) End() *ScanReport {
	sc.endTime = time.Now()
	return sc
}

func (sc *ScanReport) AddScanAttempt(a *VulnerabilityScanAttempt) *ScanReport {
	sc.scans = append(sc.scans, a)
	return sc
}

func (sc *ScanReport) GetScanAttempts() []*VulnerabilityScanAttempt {
	return sc.scans
}

func (sc *ScanReport) AddVulnerabilityReport(vr *VulnerabilityReport) *ScanReport {
	sc.vulns = append(sc.vulns, vr)
	return sc
}

func (sc *ScanReport) GetVulnerabilityReports() []*VulnerabilityReport {
	return sc.vulns
}

func (sc *ScanReport) HasVulnerabilityReport() bool {
	return len(sc.GetVulnerabilityReports()) > 0
}
