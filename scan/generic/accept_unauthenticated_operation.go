package generic

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NoAuthOperationScanID   = "generic.no-auth-operation"
	NoAuthOperationScanName = "No Auth Operation"

	NoAuthOperationVulnerabilityLevel = 0
	NoAuthOperationVulnerabilityID    = "generic.no-auth-operation"
	NoAuthOperationVulnerabilityName  = "Operation Accepts Unauthenticated Requests"
	NoAuthOperationVulnerabilityURL   = ""

	AcceptsUnauthenticatedOperationScanID   = "generic.accept-unauthenticated-operation"
	AcceptsUnauthenticatedOperationScanName = "Accept Unauthenticated Operation"

	AcceptUnauthenticatedOperationVulnerabilityLevel = 9
	AcceptUnauthenticatedOperationVulnerabilityID    = "generic.accept-unauthenticated-operation"
	AcceptUnauthenticatedOperationVulnerabilityName  = "Operation Accepts Unauthenticated Requests"
	AcceptUnauthenticatedOperationVulnerabilityURL   = ""
)

func NoAuthOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(NoAuthOperationScanID, NoAuthOperationScanName)
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NoAuthOperationVulnerabilityLevel,

			ID:   NoAuthOperationVulnerabilityID,
			Name: NoAuthOperationVulnerabilityName,
			URL:  NoAuthOperationVulnerabilityURL,

			Operation: operation,
		})
	}

	r.End()
	return r, nil
}

func AcceptUnauthenticatedOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(AcceptsUnauthenticatedOperationScanID, AcceptsUnauthenticatedOperationScanName)
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

			ID:   AcceptUnauthenticatedOperationVulnerabilityID,
			Name: AcceptUnauthenticatedOperationVulnerabilityName,
			URL:  AcceptUnauthenticatedOperationVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
