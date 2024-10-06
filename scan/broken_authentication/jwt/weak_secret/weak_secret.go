package weaksecret

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
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

func ShouldBeScanned(securitySheme auth.SecurityScheme) bool {
	if securitySheme == nil {
		return false
	}

	if _, ok := securitySheme.(*auth.JWTBearerSecurityScheme); !ok {
		return false
	}

	if !securitySheme.HasValidValue() {
		return false
	}

	valueWriter := securitySheme.GetValidValueWriter().(*jwt.JWTWriter)
	return valueWriter.IsHMACAlg()
}

var defaultJwtSecretDictionary = []string{"secret", "password", "123456", "changeme", "admin", "token"}

const jwtSecretDictionarySeclistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/scraped-JWT-secrets.txt"

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.Report, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(WeakSecretVulnerabilityScanID, WeakSecretVulnerabilityScanName, operation)

	if !ShouldBeScanned(securityScheme) {
		r.AddVulnerabilityReport(vulnReport.Skip()).End()
		return r, nil
	}

	jwtSecretDictionary := defaultJwtSecretDictionary
	if secretDictionnaryFromSeclist, err := seclist.NewSecListFromURL("JWT Secrets Dictionnary", jwtSecretDictionarySeclistUrl); err == nil {
		jwtSecretDictionary = secretDictionnaryFromSeclist.Items
	}

	secretFound := false
	valueWriter := securityScheme.GetValidValueWriter().(*jwt.JWTWriter)
	for _, secret := range jwtSecretDictionary {
		if secret == "" {
			continue
		}

		newToken, err := valueWriter.SignWithKey([]byte(secret))
		if err != nil {
			return r, nil
		}

		if newToken != valueWriter.Token.Raw {
			continue
		}

		securityScheme.SetAttackValue(newToken)
		vsa, err := scan.ScanURL(operation, &securityScheme)
		if err != nil {
			return r, err
		}
		r.AddScanAttempt(vsa)

		if scan.IsUnauthorizedStatusCodeOrSimilar(vsa.Response) {
			continue
		}

		secretFound = true
		r.WithData(&WeakSecretData{Secret: &secret})
		break
	}

	r.AddVulnerabilityReport(vulnReport.WithBooleanStatus(!secretFound)).End()

	return r, nil
}
