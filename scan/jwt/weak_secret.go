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
	WeakSecretVulnerabilitySeverityLevel = 9
	WeakSecretVulnerabilityName          = "JWT Weak Secret"
	WeakSecretVulnerabilityDescription   = "JWT secret is weak and can be easily guessed."
)

var defaultJwtSecretDictionary = []string{"secret", "password", "123456", "changeme", "admin", "token"}

const jwtSecretDictionarySeclistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/scraped-JWT-secrets.txt"

func BlankSecretScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	if !ShouldBeScanned(ss) {
		return r, nil
	}

	valueWriter := ss.GetValidValueWriter().(*jwt.JWTWriter)
	newToken, err := valueWriter.SignWithKey([]byte(""))
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
			SeverityLevel: WeakSecretVulnerabilitySeverityLevel,
			Name:          WeakSecretVulnerabilityName,
			Description:   WeakSecretVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}

func WeakHMACSecretScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	if !ShouldBeScanned(ss) {
		return r, nil
	}

	valueWriter := ss.GetValidValueWriter().(*jwt.JWTWriter)
	if !valueWriter.IsHMACAlg() {
		return r, nil
	}

	jwtSecretDictionary := defaultJwtSecretDictionary
	if secretDictionnaryFromSeclist, err := seclist.NewSecListFromURL("JWT Secrets Dictionnary", jwtSecretDictionarySeclistUrl); err == nil {
		jwtSecretDictionary = secretDictionnaryFromSeclist.Items
	}

	for _, secret := range jwtSecretDictionary {
		newToken, err := valueWriter.SignWithKey([]byte(secret))
		if err != nil {
			return r, nil
		}

		if newToken != valueWriter.Token.Raw {
			continue
		}

		ss.SetAttackValue(newToken)
		vsa, err := scan.ScanURL(o, &ss)
		r.AddScanAttempt(vsa)
		if err != nil {
			return r, err
		}

		if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: WeakSecretVulnerabilitySeverityLevel,
				Name:          WeakSecretVulnerabilityName,
				Description:   WeakSecretVulnerabilityDescription,
				Operation:     o,
			})
			break
		}
	}

	r.End()

	return r, nil
}
