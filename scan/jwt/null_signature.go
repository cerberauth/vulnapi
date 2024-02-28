package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NullSigVulnerabilitySeverityLevel = 9
	NullSigVulnerabilityName          = "JWT Null Signature"
	NullSigVulnerabilityDescription   = "JWT with null signature is accepted allowing to bypass authentication."
)

func NullSignatureScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValueWriter().(*jwt.JWTWriter)

	newToken, err := token.WithoutSignature()
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa, err := scan.ScanURL(operation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NullSigVulnerabilitySeverityLevel,
			Name:          NullSigVulnerabilityName,
			Description:   NullSigVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
