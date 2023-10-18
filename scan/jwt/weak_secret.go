package jwt

import (
	"github.com/cerberauth/vulnapi/report"
	restapi "github.com/cerberauth/vulnapi/scan/rest_api"
)

const (
	WeakSecretVulnerabilitySeverityLevel = 9
	WeakSecretVulnerabilityName          = "Weak Secret Vulnerability"
	WeakSecretVulnerabilityDescription   = "JWT is signed with a weak secret allowing attackers to issue valid JWT."
)

func BlankSecretScanHandler(url string, token string) (*report.ScanReport, error) {
	r := report.NewScanReport()

	newToken, err := createNewJWTWithClaims(token, []byte(""))
	if err != nil {
		return r, err
	}
	vsa := restapi.ScanRestAPI(url, newToken)
	r.AddScanAttempt(vsa).End()

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: WeakSecretVulnerabilitySeverityLevel,
			Name:          WeakSecretVulnerabilityName,
			Description:   WeakSecretVulnerabilityDescription,
		})
	}

	return r, nil
}

func DictSecretScanHandler(url string, token string) (*report.ScanReport, error) {
	r := report.NewScanReport()

	// Use a dictionary attack to try finding the secret

	r.End()

	return r, nil
}
