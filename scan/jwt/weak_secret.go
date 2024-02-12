package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
)

const (
	WeakSecretVulnerabilitySeverityLevel = 9
	WeakSecretVulnerabilityName          = "Weak Secret Vulnerability"
	WeakSecretVulnerabilityDescription   = "JWT is signed with a weak secret allowing attackers to issue valid JWT."
)

func BlankSecretScanHandler(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	newToken, err := createNewJWTWithClaims(token, []byte(""))
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa := restapi.ScanRestAPI(o, ss)
	r.AddScanAttempt(vsa).End()

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

func DictSecretScanHandler(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	// Use a dictionary attack to try finding the secret

	r.End()

	return r, nil
}
