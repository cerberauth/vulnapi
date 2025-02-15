package weaksecret

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/seclist"
)

type WeakSecretData struct {
	Secret *string `json:"secret,omitempty"`
}

const (
	WeakSecretVulnerabilityScanID   = "jwt.weak_secret"
	WeakSecretVulnerabilityScanName = "JWT Weak Secret"
)

var issue = report.Issue{
	ID:   "broken_authentication.weak_secret",
	Name: "JWT Secret used for signing is weak",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-weak-secret?utm_source=vulnapi",

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
	if !(securityScheme != nil && securityScheme.GetType() != auth.None && securityScheme.GetTokenFormat() != nil && *securityScheme.GetTokenFormat() == auth.JWTTokenFormat) {
		return false
	}

	valueWriter, err := jwt.NewJWTWriter(securityScheme.GetToken())
	if err != nil {
		return false
	}

	return valueWriter.IsHMACAlg()
}

var defaultJwtSecretDictionary = []string{"secret", "password", "123456", "changeme", "admin", "token"}

// From https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/scraped-JWT-secrets.txt
const jwtSecretDictionarySeclistUrl = "https://raw.githubusercontent.com/cerberauth/vulnapi/main/seclist/lists/jwt-secrets.txt"

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(WeakSecretVulnerabilityScanID, WeakSecretVulnerabilityScanName, op)
	r.AddIssueReport(vulnReport)

	if !ShouldBeScanned(securityScheme) {
		vulnReport.Skip()
		return r.End(), nil
	}

	jwtSecretDictionary := defaultJwtSecretDictionary
	if secretDictionnaryFromSeclist, err := seclist.NewSecListFromURL("JWT Secrets Dictionnary", jwtSecretDictionarySeclistUrl); err == nil {
		jwtSecretDictionary = secretDictionnaryFromSeclist.Items
	}

	valueWriter, err := jwt.NewJWTWriter(securityScheme.GetToken())
	if err != nil {
		return r.End(), err
	}

	currentToken := valueWriter.GetToken().Raw
	secret, err := bruteForceSecret(currentToken, jwtSecretDictionary, valueWriter)
	if err != nil {
		return r.End(), err
	}

	if secret != "" {
		r.WithData(&WeakSecretData{Secret: &secret})
		vulnReport.Fail()
	} else {
		vulnReport.Pass()
	}
	r.AddIssueReport(vulnReport)

	return r.End(), nil
}

func bruteForceSecret(currentToken string, jwtSecretDictionary []string, valueWriter *jwt.JWTWriter) (string, error) {
	type result struct {
		secret string
		err    error
	}

	results := make(chan result, len(jwtSecretDictionary))
	localValueWriter := valueWriter.Clone()

	for _, secret := range jwtSecretDictionary {
		go func(secret string) {
			if secret == "" {
				results <- result{"", nil}
				return
			}

			newToken, err := localValueWriter.SignWithKey([]byte(secret))
			if err != nil {
				results <- result{"", err}
				return
			}

			if newToken != currentToken {
				results <- result{"", nil}
				return
			}

			results <- result{secret, nil}
		}(secret)
	}

	for range jwtSecretDictionary {
		res := <-results
		if res.err != nil {
			return "", res.err
		}
		if res.secret != "" {
			return res.secret, nil
		}
	}

	return "", nil
}
