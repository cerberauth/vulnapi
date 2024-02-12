package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
	"github.com/golang-jwt/jwt/v5"
)

const (
	NotVerifiedVulnerabilitySeverityLevel = 9
	NotVerifiedVulnerabilityName          = "JWT Not Verified"
	NotVerifiedVulnerabilityDescription   = "JWT is not verified."
)

func NotVerifiedScanHandler(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	newTokenA, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodHS256, []byte("a"))
	if err != nil {
		return r, err
	}

	newTokenB, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodHS256, []byte("b"))
	if err != nil {
		return r, err
	}

	ss.SetAttackValue(newTokenA)
	vsa1 := restapi.ScanRestAPI(o, ss)
	r.AddScanAttempt(vsa1)

	ss.SetAttackValue(newTokenB)
	vsa2 := restapi.ScanRestAPI(o, ss)
	r.AddScanAttempt(vsa2)

	r.End()

	if vsa1.Response.StatusCode != vsa2.Response.StatusCode {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NotVerifiedVulnerabilitySeverityLevel,
			Name:          NotVerifiedVulnerabilityName,
			Description:   NotVerifiedVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	return r, nil
}
