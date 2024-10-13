package fingerprint

import (
	"io"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	DiscoverFingerPrintScanID   = "discover.server_signature"
	DiscoverFingerPrintScanName = "Server Signature Discovery"
)

type FingerPrintApp struct {
	Name    string  `json:"name" yaml:"name"`
	Version *string `json:"version,omitempty"`
}

type FingerPrintData struct {
	CertificateAuthority []FingerPrintApp `json:"certificate_authority" yaml:"certificate_authority"`
	Hosting              []FingerPrintApp `json:"hosting" yaml:"hosting"`
	OS                   []FingerPrintApp `json:"os" yaml:"os"`
	Softwares            []FingerPrintApp `json:"softwares" yaml:"softwares"`
	Databases            []FingerPrintApp `json:"databases" yaml:"databases"`
	Servers              []FingerPrintApp `json:"servers" yaml:"servers"`
	ServerExtensions     []FingerPrintApp `json:"server_extensions" yaml:"server_extensions"`
	AuthServices         []FingerPrintApp `json:"auth_services" yaml:"auth_services"`
	CDNs                 []FingerPrintApp `json:"cdns" yaml:"cdns"`
	Caching              []FingerPrintApp `json:"cache" yaml:"cache"`
	Languages            []FingerPrintApp `json:"languages" yaml:"languages"`
	Frameworks           []FingerPrintApp `json:"frameworks" yaml:"frameworks"`
	SecurityServices     []FingerPrintApp `json:"security_services" yaml:"security_services"`
}

var issue = report.Issue{
	ID:   "discover.fingerprint",
	Name: "Service Fingerprinting",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

func appendIfMissing(slice []FingerPrintApp, app FingerPrintApp) []FingerPrintApp {
	for _, element := range slice {
		if element.Name == app.Name {
			return slice
		}
	}
	return append(slice, app)
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverFingerPrintScanID, DiscoverFingerPrintScanName, operation)

	attempt, err := scan.ScanURL(operation, &securityScheme)
	r.AddScanAttempt(attempt)
	if err != nil {
		return r.AddIssueReport(vulnReport.Skip()).End(), err
	}

	if attempt.Err != nil {
		return r.AddIssueReport(vulnReport.Skip()).End(), attempt.Err
	}

	resp := attempt.Response
	data, _ := io.ReadAll(resp.Body)

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		return r.AddIssueReport(vulnReport.Skip()).End(), err
	}

	fingerprints := wappalyzerClient.FingerprintWithInfo(resp.Header, data)
	reportData := FingerPrintData{}
	fingerPrintIdentifier := false
	for name, fingerprint := range fingerprints {
		if len(fingerprint.Categories) == 0 {
			continue
		}

		for _, category := range fingerprint.Categories {
			switch category {
			case "SSL/TLS certificate authorities":
				fingerPrintIdentifier = true
				reportData.CertificateAuthority = appendIfMissing(reportData.CertificateAuthority, FingerPrintApp{Name: name})
			case "Operating systems":
				fingerPrintIdentifier = true
				reportData.OS = appendIfMissing(reportData.OS, FingerPrintApp{Name: name})
			case "Containers", "PaaS", "IaaS", "Hosting":
				fingerPrintIdentifier = true
				reportData.Hosting = appendIfMissing(reportData.Hosting, FingerPrintApp{Name: name})
			case "CMS", "Ecommerce", "Wikis", "Blogs", "LMS", "DMS", "Page builders", "Static site generator":
				fingerPrintIdentifier = true
				reportData.Softwares = appendIfMissing(reportData.Softwares, FingerPrintApp{Name: name})
			case "Databases":
				fingerPrintIdentifier = true
				reportData.Databases = appendIfMissing(reportData.Databases, FingerPrintApp{Name: name})
			case "Web servers", "Reverse proxies":
				fingerPrintIdentifier = true
				reportData.Servers = appendIfMissing(reportData.Servers, FingerPrintApp{Name: name})
			case "Web server extensions":
				fingerPrintIdentifier = true
				reportData.ServerExtensions = appendIfMissing(reportData.ServerExtensions, FingerPrintApp{Name: name})
			case "Authentication":
				fingerPrintIdentifier = true
				reportData.AuthServices = appendIfMissing(reportData.AuthServices, FingerPrintApp{Name: name})
			case "CDN":
				fingerPrintIdentifier = true
				reportData.CDNs = appendIfMissing(reportData.CDNs, FingerPrintApp{Name: name})
			case "Caching":
				fingerPrintIdentifier = true
				reportData.Caching = appendIfMissing(reportData.Caching, FingerPrintApp{Name: name})
			case "JavaScript frameworks", "Web frameworks":
				fingerPrintIdentifier = true
				reportData.Frameworks = appendIfMissing(reportData.Frameworks, FingerPrintApp{Name: name})
			case "Programming languages":
				fingerPrintIdentifier = true
				reportData.Languages = appendIfMissing(reportData.Languages, FingerPrintApp{Name: name})
			case "Security":
				fingerPrintIdentifier = true
				reportData.SecurityServices = appendIfMissing(reportData.SecurityServices, FingerPrintApp{Name: name})
			}
		}
	}

	vulnReport.WithBooleanStatus(!fingerPrintIdentifier)
	r.WithData(reportData).AddIssueReport(vulnReport).End()

	return r, nil
}
