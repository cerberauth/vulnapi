package bestpractices

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
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
	CSPHTTPHeaderSeverityLevel                                  = 1
	CSPHTTPHeaderIsNotSetVulnerabilityName                      = "CSP Header is not set"
	CSPHTTPHeaderIsNotSetVulnerabilityDescription               = "No Content Security Policy (CSP) Header has been detected in HTTP Response."
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName        = "CSP frame-ancestors policy is not set"
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription = "No frame-ancestors policy has been set in CSP HTTP Response Header."

	HSTSHTTPHeaderSeverityLevel                    = 1
	HSTSHTTPHeaderIsNotSetVulnerabilityName        = "HSTS Header is not set"
	HSTSHTTPHeaderIsNotSetVulnerabilityDescription = "No HSTS Header has been detected in HTTP Response."

	CORSHTTPHeaderSeverityLevel                       = 1
	CORSHTTPHeaderIsNotSetVulnerabilityName           = "CORS Header is not set"
	CORSHTTPHeaderIsNotSetVulnerabilityDescription    = "No CORS Header has been detected in HTTP Response."
	CORSHTTPHeaderIsPermisiveVulnerabilityName        = "CORS Header is set but permissive"
	CORSHTTPHeaderIsPermisiveVulnerabilityDescription = "CORS Header has been detected in HTTP Response but is permissive."

	XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel            = 1
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName        = "X-Content-Type-Options Header is not set"
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityDescription = "No X-Content-Type-Options Header has been detected in HTTP Response."

	XFrameOptionsHTTPHeaderIsNotSetSeverityLevel            = 1
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName        = "X-Frame-Options Header is not set"
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityDescription = "No X-Frame-Options Header has been detected in HTTP Response."
)

func checkCSPHeader(o *request.Operation, headers http.Header, r *report.ScanReport) bool {
	cspHeader := headers.Get(CSPHTTPHeader)
	if cspHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CSPHTTPHeaderSeverityLevel,
			Name:          CSPHTTPHeaderIsNotSetVulnerabilityName,
			Description:   CSPHTTPHeaderIsNotSetVulnerabilityDescription,
			Url:           o.Url,
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
		Url:           o.Url,
	})

	return false
}

func CheckCORSAllowOrigin(o *request.Operation, headers http.Header, r *report.ScanReport) bool {
	allowOrigin := headers.Get(CORSOriginHTTPHeader)
	if allowOrigin == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CORSHTTPHeaderSeverityLevel,
			Name:          CORSHTTPHeaderIsNotSetVulnerabilityName,
			Description:   CORSHTTPHeaderIsNotSetVulnerabilityDescription,
			Url:           o.Url,
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
		Url:           o.Url,
	})

	return false
}

func HTTPHeadersBestPracticesScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	token := ss.GetValidValue().(string)

	ss.SetAttackValue(token)
	vsa, err := request.ScanURL(o, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Err != nil {
		return r, vsa.Err
	}

	checkCSPHeader(o, vsa.Response.Header, r)
	CheckCORSAllowOrigin(o, vsa.Response.Header, r)

	if hstsHeader := vsa.Response.Header.Get(HSTSHTTPHeader); hstsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HSTSHTTPHeaderSeverityLevel,
			Name:          HSTSHTTPHeaderIsNotSetVulnerabilityName,
			Description:   HSTSHTTPHeaderIsNotSetVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	if xContentTypeOptionsHeader := vsa.Response.Header.Get(XContentTypeOptionsHTTPHeader); xContentTypeOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel,
			Name:          XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
			Description:   XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	if xFrameOptionsHeader := vsa.Response.Header.Get(XFrameOptionsHTTPHeader); xFrameOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XFrameOptionsHTTPHeaderIsNotSetSeverityLevel,
			Name:          XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
			Description:   XFrameOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	return r, nil
}
