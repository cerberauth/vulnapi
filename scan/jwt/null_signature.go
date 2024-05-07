package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NullSignatureScanID   = "jwt.null_signature"
	NullSignatureScanName = "JWT Null Signature"

	NullSigVulnerabilitySeverityLevel     = 9
	NullSigVulnerabilityOWASP2023Category = report.OWASP2023BrokenAuthCategory

	NullSigVulnerabilityID   = "broken_authentication.jwt_null_signature"
	NullSigVulnerabilityName = "JWT Null Signature"
	NullSigVulnerabilityURL  = ""
)

func NullSignatureScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	if !ShouldBeScanned(ss) {
		return nil, nil
	}

	var valueWriter *jwt.JWTWriter
	if ss.HasValidValue() {
		valueWriter = ss.GetValidValueWriter().(*jwt.JWTWriter)
	} else {
		valueWriter, _ = jwt.NewJWTWriter(jwt.FakeJWT)
	}

	r := report.NewScanReport(NullSignatureScanID, NullSignatureScanName)
	newToken, err := valueWriter.WithoutSignature()
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa, err := scan.ScanURL(operation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NullSigVulnerabilitySeverityLevel,

			OWASP2023Category: NullSigVulnerabilityOWASP2023Category,

			ID:   NullSigVulnerabilityID,
			Name: NullSigVulnerabilityName,
			URL:  NullSigVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
