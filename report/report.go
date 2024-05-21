package report

import (
	"net/http"
	"time"

	"github.com/cerberauth/vulnapi/internal/request"
)

type VulnerabilityScanAttempt struct {
	Request  *http.Request  `json:"-"`
	Response *http.Response `json:"-"`

	Err error `json:"error"`
}

type ScanReport struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	Operation *request.Operation `json:"operation"`

	Data  interface{}                 `json:"data" yaml:"data"`
	Scans []*VulnerabilityScanAttempt `json:"scans"`
	Vulns []*VulnerabilityReport      `json:"vulnerabilities"`
}

func NewScanReport(id string, name string, operaton *request.Operation) *ScanReport {
	return &ScanReport{
		ID:        id,
		Name:      name,
		StartTime: time.Now(),

		Operation: operaton,

		Scans: []*VulnerabilityScanAttempt{},
		Vulns: []*VulnerabilityReport{},
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

func (sc *ScanReport) WithData(data interface{}) *ScanReport {
	sc.Data = data
	return sc
}

func (sc *ScanReport) GetData() interface{} {
	return sc.Data
}

func (sc *ScanReport) HasData() bool {
	return sc.Data != nil
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

func (sc *ScanReport) GetErrors() []error {
	var errors []error
	for _, sa := range sc.GetScanAttempts() {
		if sa != nil && sa.Err != nil {
			errors = append(errors, sa.Err)
		}
	}
	return errors
}

func (sc *ScanReport) GetFailedVulnerabilityReports() []*VulnerabilityReport {
	var failedReports []*VulnerabilityReport
	for _, vr := range sc.GetVulnerabilityReports() {
		if vr.HasFailed() {
			failedReports = append(failedReports, vr)
		}
	}
	return failedReports
}

func (sc *ScanReport) HasFailedVulnerabilityReport() bool {
	return len(sc.GetFailedVulnerabilityReports()) > 0
}
