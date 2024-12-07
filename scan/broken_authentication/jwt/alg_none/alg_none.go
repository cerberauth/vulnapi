package algnone

import (
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

type AlgNoneData struct {
	Alg string `json:"alg"`
}

const (
	AlgNoneJwtScanID   = "jwt.alg_none"
	AlgNoneJwtScanName = "JWT None Algorithm"
)

var issue = report.Issue{
	ID:   "broken_authentication.alg_none",
	Name: "JWT Algorithm None is accepted",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-alg-none?utm_source=vulnapi",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_BrokenAuthentication,
		CWE:   report.CWE_345_Insufficient_Verification_Authenticity,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
		Score:   9.3,
	},
}

func ShouldBeScanned(securityScheme *auth.SecurityScheme) bool {
	return securityScheme != nil && securityScheme.GetType() != auth.None && securityScheme.GetTokenFormat() != nil && *securityScheme.GetTokenFormat() == auth.JWTTokenFormat
}

var algs = []string{
	"none",
	"NONE",
	"None",
	"nOnE",
}

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	issueReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(AlgNoneJwtScanID, AlgNoneJwtScanName, op)

	if !ShouldBeScanned(securityScheme) {
		issueReport.Skip()
		r.AddIssueReport(issueReport).End()
		return r, nil
	}

	var token string
	if securityScheme.HasValidValue() {
		token = securityScheme.GetToken()
	} else {
		token = jwt.FakeJWT
	}

	valueWriter, err := jwt.NewJWTWriter(token)
	if err != nil {
		return r, err
	}

	if valueWriter.GetToken().Method.Alg() == jwtlib.SigningMethodNone.Alg() {
		r.AddIssueReport(issueReport.Fail()).End()
		return r, nil
	}
	valueWriter = jwt.NewJWTWriterWithValidClaims(valueWriter)

	method := &signingMethodNone{}
	for _, alg := range algs {
		method.SetAlg(alg)
		vsa, err := scanWithAlg(method, valueWriter, securityScheme, op)
		if err != nil {
			return r, err
		}
		r.AddScanAttempt(vsa)
		issueReport.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(vsa.Response))

		if issueReport.HasFailed() {
			r.WithData(&AlgNoneData{Alg: strings.Clone(alg)})
			break
		}
	}

	r.AddIssueReport(issueReport).End()
	return r, nil
}

func scanWithAlg(method jwtlib.SigningMethod, valueWriter *jwt.JWTWriter, securityScheme *auth.SecurityScheme, op *operation.Operation) (*scan.IssueScanAttempt, error) {
	newToken, err := valueWriter.SignWithMethodAndKey(method, jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		return nil, err
	}

	if err = securityScheme.SetAttackValue(newToken); err != nil {
		return nil, err
	}

	vsa, err := scan.ScanURL(op, securityScheme)
	if err != nil {
		return nil, err
	}
	return vsa, nil
}
