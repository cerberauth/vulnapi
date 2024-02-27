package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const (
	WeakSecretVulnerabilitySeverityLevel = 9
	WeakSecretVulnerabilityName          = "JWT Weak Secret"
	WeakSecretVulnerabilityDescription   = "JWT secret is weak and can be easily guessed."
)

func BlankSecretScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	newToken, err := createNewJWTWithClaims(token, []byte(""))
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa, err := request.ScanURL(o, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: WeakSecretVulnerabilitySeverityLevel,
			Name:          WeakSecretVulnerabilityName,
			Description:   WeakSecretVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	return r, nil
}

func DictSecretScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	// TODO: Use a dictionary attack to try finding the secret

	r.End()

	return r, nil
}
