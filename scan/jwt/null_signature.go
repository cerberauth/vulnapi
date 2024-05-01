package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NullSignatureScanID   = "jwt.null-signature"
	NullSignatureScanName = "JWT Null Signature"

	NullSigSeverityLevel     = 9
	NullSigVulnerabilityID   = "jwt.null-signature"
	NullSigVulnerabilityName = "JWT Null Signature"
	NullSigVulnerabilityURL  = ""
)

func NullSignatureScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(NullSignatureScanID, NullSignatureScanName)
	if !ShouldBeScanned(ss) {
		return r, nil
	}

	valueWriter := ss.GetValidValueWriter().(*jwt.JWTWriter)
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
			SeverityLevel: NullSigSeverityLevel,

			ID:   NullSigVulnerabilityID,
			Name: NullSigVulnerabilityName,
			URL:  NullSigVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
