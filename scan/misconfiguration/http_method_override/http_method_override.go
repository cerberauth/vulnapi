package httpmethodoverride

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPMethodOverrideScanID   = "misconfiguration.http_method_override"
	HTTPMethodOverrideScanName = "HTTP Method Override Misconfiguration"
)

var httpMethodOverrideIssue = report.Issue{
	ID:   "security_misconfiguration.http_method_allow_override",
	Name: "Possible HTTP Method Override detected",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/security-misconfiguration/http-method-allow-override?utm_source=vulnapi",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_16_Configuration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var httpMethodOverrideAuthenticationByPassIssue = report.Issue{
	ID:   "security_misconfiguration.http_method_override_authentication_bypass",
	Name: "Possible HTTP Method Override with authentication bypass detected",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/security-misconfiguration/http-method-allow-override?utm_source=vulnapi",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_287_Improper_Authentication,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
		Score:   8.8,
	},
}

var httpMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Http-Method-Override",
	"X-HTTP-Method",
	"X-Http-Method",
	"X-Method-Override",
}

var methodOverrideQueryParams = []string{
	"_method",
	"method",
	"httpMethod",
	"_httpMethod",
}

func ScanHandler(op *operation.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	var err error
	var newOperation *operation.Operation

	httpMethodOverrideIssueReport := report.NewIssueReport(httpMethodOverrideIssue).WithOperation(op).WithSecurityScheme(securityScheme)
	httpMethodOverrideAuthenticationByPassIssueReport := report.NewIssueReport(httpMethodOverrideAuthenticationByPassIssue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(HTTPMethodOverrideScanID, HTTPMethodOverrideScanName, op)

	newOperation, err = op.Clone()
	if err != nil {
		return r, err
	}

	initialAttempt, err := scan.ScanURL(newOperation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(initialAttempt)

	if initialAttempt.Response.GetStatusCode() == http.StatusMethodNotAllowed {
		r.AddIssueReport(httpMethodOverrideIssueReport.Skip()).End()
		return r, nil
	}

	var methodAttempt *scan.IssueScanAttempt
	for _, method := range httpMethods {
		if method == op.Method {
			continue
		}

		newOperation, err = op.Clone()
		if err != nil {
			return r, err
		}

		newOperation.Method = method
		methodAttempt, err = scan.ScanURL(newOperation, &securityScheme)
		if methodAttempt != nil {
			r.AddScanAttempt(methodAttempt)
		}

		if err == nil && methodAttempt.Response.GetStatusCode() == http.StatusMethodNotAllowed {
			break
		}
	}

	if err != nil {
		r.AddIssueReport(httpMethodOverrideIssueReport).AddIssueReport(httpMethodOverrideAuthenticationByPassIssueReport).End()
		return r, err
	}

	if methodAttempt.Response.GetStatusCode() == initialAttempt.Response.GetStatusCode() {
		r.AddIssueReport(httpMethodOverrideIssueReport.Pass()).AddIssueReport(httpMethodOverrideAuthenticationByPassIssueReport.Skip()).End()
		return r, nil
	}

	var attemptFailed = false
	var attempt *scan.IssueScanAttempt
	newOperationMethod := methodAttempt.Request.GetMethod()
	for _, header := range methodOverrideHeaders {
		newOperation, err = op.Clone()
		if err != nil {
			return r, err
		}

		newOperation.Header.Set(header, op.Method)
		newOperation.Method = newOperationMethod
		attempt, err = scan.ScanURL(newOperation, &securityScheme)
		if attempt != nil {
			r.AddScanAttempt(attempt)
		}

		if err == nil && attempt.Response.GetStatusCode() == initialAttempt.Response.GetStatusCode() {
			attemptFailed = true
			break
		}
	}

	if !attemptFailed {
		for _, queryParam := range methodOverrideQueryParams {
			newOperation, err = op.Clone()
			if err != nil {
				return r, err
			}

			newOperationQueryValues := newOperation.URL.Query()
			newOperationQueryValues.Set(queryParam, op.Method)
			newOperation.URL.RawQuery = newOperationQueryValues.Encode()
			newOperation.Method = newOperationMethod
			attempt, err = scan.ScanURL(newOperation, &securityScheme)
			if attempt != nil {
				r.AddScanAttempt(attempt)
			}

			if err == nil && attempt.Response.GetStatusCode() == initialAttempt.Response.GetStatusCode() {
				attemptFailed = true
				break
			}
		}
	}

	if !attemptFailed {
		r.AddIssueReport(httpMethodOverrideIssueReport.Pass()).AddIssueReport(httpMethodOverrideAuthenticationByPassIssueReport.Skip()).End()
		return r, nil
	}

	r.AddIssueReport(httpMethodOverrideIssueReport.Fail())
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		return r.AddIssueReport(httpMethodOverrideAuthenticationByPassIssueReport.Skip()).End(), nil
	}

	noAuthSecurityScheme := auth.SecurityScheme(auth.NewNoAuthSecurityScheme())
	attempt, err = scan.ScanURL(newOperation, &noAuthSecurityScheme)
	if err != nil {
		return r, err
	}
	httpMethodOverrideAuthenticationByPassIssueReport.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(attempt.Response))
	r.AddIssueReport(httpMethodOverrideAuthenticationByPassIssueReport).AddScanAttempt(attempt).End()

	return r, nil
}
