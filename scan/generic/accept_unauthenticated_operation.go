package generic

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NoAuthOperationVulnerabilityLevel       = 0
	NoAuthOperationVulnerabilityName        = "Operation Accepts Unauthenticated Requests"
	NoAuthOperationVulnerabilityDescription = "The operation accepts unauthenticated requests or the authenticated scheme has not been detected. This can lead to unauthorized access and security issues."

	AcceptUnauthenticatedOperationVulnerabilityLevel       = 9
	AcceptUnauthenticatedOperationVulnerabilityName        = "Operation Accepts Unauthenticated Requests"
	AcceptUnauthenticatedOperationVulnerabilityDescription = "The operation accepts unauthenticated requests or the authenticated scheme has not been detected. This can lead to unauthorized access and security issues."
)

func NoAuthOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NoAuthOperationVulnerabilityLevel,
			Name:          NoAuthOperationVulnerabilityName,
			Description:   NoAuthOperationVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}

func AcceptUnauthenticatedOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		return r, nil
	}

	noAuthSecurityScheme := auth.SecurityScheme(auth.NewNoAuthSecurityScheme())
	vsa, err := scan.ScanURL(operation, &noAuthSecurityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(vsa).End()

	if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: AcceptUnauthenticatedOperationVulnerabilityLevel,
			Name:          AcceptUnauthenticatedOperationVulnerabilityName,
			Description:   AcceptUnauthenticatedOperationVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
