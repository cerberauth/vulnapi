package jwt

import (
	"github.com/cerberauth/vulnapi/report"
	restapi "github.com/cerberauth/vulnapi/scan/rest_api"
	"github.com/golang-jwt/jwt/v5"
)

const (
	NotVerifiedVulnerabilitySeverityLevel = 9
	NotVerifiedVulnerabilityName          = "JWT Not Verified"
	NotVerifiedVulnerabilityDescription   = "JWT is not verified."
)

func NotVerifiedScanHandler(url string, token string) (*report.ScanReport, error) {
	r := report.NewScanReport()

	newTokenA, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodHS256, []byte("a"))
	if err != nil {
		return r, err
	}

	newTokenB, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodHS256, []byte("b"))
	if err != nil {
		return r, err
	}

	vsa1 := restapi.ScanRestAPI(url, newTokenA)
	r.AddScanAttempt(vsa1)

	vsa2 := restapi.ScanRestAPI(url, newTokenB)
	r.AddScanAttempt(vsa2)

	r.End()

	if vsa1.Response.StatusCode != vsa2.Response.StatusCode {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NotVerifiedVulnerabilitySeverityLevel,
			Name:          NotVerifiedVulnerabilityName,
			Description:   NotVerifiedVulnerabilityDescription,
		})
	}

	return r, nil
}
