package jwt

import (
	"strings"

	"github.com/cerberauth/vulnapi/report"
	restapi "github.com/cerberauth/vulnapi/scan/rest_api"
)

const (
	NullSigVulnerabilitySeverityLevel = 9
	NullSigVulnerabilityName          = "JWT Null Signature"
	NullSigVulnerabilityDescription   = "JWT with null signature is accepted allowing to bypass authentication."
)

func createNewJWTWithoutSignature(originalTokenString string) (string, error) {
	newTokenString, err := createNewJWTWithClaims(originalTokenString, []byte(""))
	if err != nil {
		return "", err
	}

	parts := strings.Split(newTokenString, ".")
	return strings.Join([]string{parts[0], parts[1], ""}, "."), nil
}

func NullSignatureScanHandler(url string, token string) (*report.ScanReport, error) {
	r := report.NewScanReport()

	newToken, err := createNewJWTWithoutSignature(token)
	if err != nil {
		return r, err
	}
	vsa := restapi.ScanRestAPI(url, newToken)
	r.AddScanAttempt(vsa).End()

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NullSigVulnerabilitySeverityLevel,
			Name:          NullSigVulnerabilityName,
			Description:   NullSigVulnerabilityDescription,
		})
	}

	return r, nil
}
