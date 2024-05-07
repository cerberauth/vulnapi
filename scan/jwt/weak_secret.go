package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/seclist"
)

const (
	WeakSecretVulnerabilityScanID   = "jwt.weak_secret"
	WeakSecretVulnerabilityScanName = "JWT Weak Secret"

	WeakSecretVulnerabilitySeverityLevel     = 9
	WeakSecretVulnerabilityOWASP2023Category = report.OWASP2023BrokenAuthCategory

	WeakSecretVulnerabilityID   = "broken_authentication.jwt_weak_secret"
	WeakSecretVulnerabilityName = "JWT Weak Secret"
	WeakSecretVulnerabilityURL  = ""
)

var defaultJwtSecretDictionary = []string{"secret", "password", "123456", "changeme", "admin", "token"}

const jwtSecretDictionarySeclistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/scraped-JWT-secrets.txt"

func WeakHMACSecretScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	if !ShouldBeScanned(ss) {
		return nil, nil
	}

	if !ss.HasValidValue() {
		return nil, nil
	}

	valueWriter := ss.GetValidValueWriter().(*jwt.JWTWriter)
	if !valueWriter.IsHMACAlg() {
		return nil, nil
	}

	r := report.NewScanReport(WeakSecretVulnerabilityScanID, WeakSecretVulnerabilityScanName)
	jwtSecretDictionary := defaultJwtSecretDictionary
	if secretDictionnaryFromSeclist, err := seclist.NewSecListFromURL("JWT Secrets Dictionnary", jwtSecretDictionarySeclistUrl); err == nil {
		jwtSecretDictionary = secretDictionnaryFromSeclist.Items
	}

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

		ss.SetAttackValue(newToken)
		vsa, err := scan.ScanURL(o, &ss)
		r.AddScanAttempt(vsa).End()
		if err != nil {
			return r, err
		}

		if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: WeakSecretVulnerabilitySeverityLevel,

				ID:   BlankSecretVulnerabilityID,
				Name: WeakSecretVulnerabilityName,
				URL:  BlankSecretVulnerabilityURL,

				Operation: o,
			})
			break
		}
	}

	r.End()

	return r, nil
}
