package jwt

import (
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
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

func NullSignatureScanHandler(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	newToken, err := createNewJWTWithoutSignature(token)
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa := restapi.ScanRestAPI(o, ss)
	r.AddScanAttempt(vsa).End()

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NullSigVulnerabilitySeverityLevel,
			Name:          NullSigVulnerabilityName,
			Description:   NullSigVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	return r, nil
}
