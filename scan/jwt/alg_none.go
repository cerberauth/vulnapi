package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AlgNoneVulnerabilitySeverityLevel = 9
	AlgNoneVulnerabilityName          = "JWT None Algorithm"
	AlgNoneVulnerabilityDescription   = "JWT with none algorithm is accepted allowing to bypass authentication."
)

func AlgNoneJwtScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	newToken, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa, err := request.ScanURL(o, &ss)
	if err != nil {
		return r, err
	}
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
