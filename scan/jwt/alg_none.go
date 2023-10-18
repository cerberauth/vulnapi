package jwt

import (
	"github.com/cerberauth/vulnapi/report"
	restapi "github.com/cerberauth/vulnapi/scan/rest_api"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AlgNoneVulnerabilitySeverityLevel = 9
	AlgNoneVulnerabilityName          = "JWT Alg None"
	AlgNoneVulnerabilityDescription   = "JWT accepts none algorithm and does verify jwt."
)

func AlgNoneJwtScanHandler(url string, token string) (*report.ScanReport, error) {
	r := report.NewScanReport()

	newToken, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return r, err
	}
	vsa := restapi.ScanRestAPI(url, newToken)
	r.AddScanAttempt(vsa).End()

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: AlgNoneVulnerabilitySeverityLevel,
			Name:          AlgNoneVulnerabilityName,
			Description:   AlgNoneVulnerabilityDescription,
		})
	}

	return r, nil
}
