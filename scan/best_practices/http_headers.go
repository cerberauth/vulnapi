package bestpractices

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	CSPHTTPHeader                 = "Content-Security-Policy"
	HSTSHTTPHeader                = "Strict-Transport-Security"
	CORSOriginHTTPHeader          = "Access-Control-Allow-Origin"
	XContentTypeOptionsHTTPHeader = "X-Content-Type-Options"
	XFrameOptionsHTTPHeader       = "X-Frame-Options"
)

const (
	CSPHTTPHeaderSeverityLevel                                  = 0
	CSPHTTPHeaderIsNotSetVulnerabilityName                      = "CSP Header is not set"
	CSPHTTPHeaderIsNotSetVulnerabilityDescription               = "No Content Security Policy (CSP) Header has been detected in HTTP Response."
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName        = "CSP frame-ancestors policy is not set"
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription = "No frame-ancestors policy has been set in CSP HTTP Response Header."

	HSTSHTTPHeaderSeverityLevel                    = 0
	HSTSHTTPHeaderIsNotSetVulnerabilityName        = "HSTS Header is not set"
	HSTSHTTPHeaderIsNotSetVulnerabilityDescription = "No HSTS Header has been detected in HTTP Response."

	CORSHTTPHeaderSeverityLevel                       = 0
	CORSHTTPHeaderIsNotSetVulnerabilityName           = "CORS Header is not set"
	CORSHTTPHeaderIsNotSetVulnerabilityDescription    = "No CORS Header has been detected in HTTP Response."
	CORSHTTPHeaderIsPermisiveVulnerabilityName        = "CORS Header is set but permissive"
	CORSHTTPHeaderIsPermisiveVulnerabilityDescription = "CORS Header has been detected in HTTP Response but is permissive."

	XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel            = 0
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName        = "X-Content-Type-Options Header is not set"
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityDescription = "No X-Content-Type-Options Header has been detected in HTTP Response."

	XFrameOptionsHTTPHeaderIsNotSetSeverityLevel            = 0
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName        = "X-Frame-Options Header is not set"
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityDescription = "No X-Frame-Options Header has been detected in HTTP Response."
)

func checkCSPHeader(operation *request.Operation, headers http.Header, r *report.ScanReport) bool {
	cspHeader := headers.Get(CSPHTTPHeader)
	if cspHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CSPHTTPHeaderSeverityLevel,
			Name:          CSPHTTPHeaderIsNotSetVulnerabilityName,
			Description:   CSPHTTPHeaderIsNotSetVulnerabilityDescription,
			Operation:     operation,
		})

		return false
	}

	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "frame-ancestors") {
			// Check if frame-ancestors directive is not equal to "none"
			if strings.Contains(directive, "none") {
				return true
			}
		}
	}

	r.AddVulnerabilityReport(&report.VulnerabilityReport{
		SeverityLevel: CSPHTTPHeaderSeverityLevel,
		Name:          CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		Description:   CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription,
		Operation:     operation,
	})

	return false
}

func CheckCORSAllowOrigin(operation *request.Operation, headers http.Header, r *report.ScanReport) bool {
	allowOrigin := headers.Get(CORSOriginHTTPHeader)
	if allowOrigin == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CORSHTTPHeaderSeverityLevel,
			Name:          CORSHTTPHeaderIsNotSetVulnerabilityName,
			Description:   CORSHTTPHeaderIsNotSetVulnerabilityDescription,
			Operation:     operation,
		})

		return false
	}

	// Check if the Access-Control-Allow-Origin header is not "*" (wildcard)
	if allowOrigin != "*" {
		return true
	}

	r.AddVulnerabilityReport(&report.VulnerabilityReport{
		SeverityLevel: CORSHTTPHeaderSeverityLevel,
		Name:          CORSHTTPHeaderIsPermisiveVulnerabilityName,
		Description:   CORSHTTPHeaderIsPermisiveVulnerabilityDescription,
		Operation:     operation,
	})

	return false
}

func HTTPHeadersBestPracticesScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	ss.SetAttackValue(ss.GetValidValue())
	vsa, err := scan.ScanURL(operation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Err != nil {
		return r, vsa.Err
	}

	checkCSPHeader(operation, vsa.Response.Header, r)
	CheckCORSAllowOrigin(operation, vsa.Response.Header, r)

	if hstsHeader := vsa.Response.Header.Get(HSTSHTTPHeader); hstsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HSTSHTTPHeaderSeverityLevel,
			Name:          HSTSHTTPHeaderIsNotSetVulnerabilityName,
			Description:   HSTSHTTPHeaderIsNotSetVulnerabilityDescription,
			Operation:     operation,
		})
	}

	if xContentTypeOptionsHeader := vsa.Response.Header.Get(XContentTypeOptionsHTTPHeader); xContentTypeOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel,
			Name:          XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
			Description:   XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
			Operation:     operation,
		})
	}

	if xFrameOptionsHeader := vsa.Response.Header.Get(XFrameOptionsHTTPHeader); xFrameOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XFrameOptionsHTTPHeaderIsNotSetSeverityLevel,
			Name:          XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
			Description:   XFrameOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
