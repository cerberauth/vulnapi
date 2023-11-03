package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AlgNoneVulnerabilitySeverityLevel = 9
	AlgNoneVulnerabilityName          = "JWT Alg None"
	AlgNoneVulnerabilityDescription   = "JWT accepts none algorithm and does verify jwt."
)

func AlgNoneJwtScanHandler(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	newToken, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa := restapi.ScanRestAPI(o, ss)
	r.AddScanAttempt(vsa).End()

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: AlgNoneVulnerabilitySeverityLevel,
			Name:          AlgNoneVulnerabilityName,
			Description:   AlgNoneVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	return r, nil
}
