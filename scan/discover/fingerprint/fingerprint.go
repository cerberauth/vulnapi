package fingerprint

import (
	"context"
	_ "embed"
	"errors"
	"strings"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("fingerprint", checkYAML)

type FingerPrintApp struct {
	Name    string  `json:"name" yaml:"name"`
	Version *string `json:"version,omitempty"`
}

type FingerPrintData struct {
	CertificateAuthority []FingerPrintApp `json:"certificate_authority" yaml:"certificate_authority"`
	Hosting              []FingerPrintApp `json:"hosting" yaml:"hosting"`
	OS                   []FingerPrintApp `json:"os" yaml:"os"`
	Softwares            []FingerPrintApp `json:"softwares" yaml:"softwares"`
	Databases            []FingerPrintApp `json:"databases" yaml:"databases"`
	Servers              []FingerPrintApp `json:"servers" yaml:"servers"`
	ServerExtensions     []FingerPrintApp `json:"server_extensions" yaml:"server_extensions"`
	AuthServices         []FingerPrintApp `json:"auth_services" yaml:"auth_services"`
	CDNs                 []FingerPrintApp `json:"cdns" yaml:"cdns"`
	Caching              []FingerPrintApp `json:"cache" yaml:"cache"`
	Languages            []FingerPrintApp `json:"languages" yaml:"languages"`
	Frameworks           []FingerPrintApp `json:"frameworks" yaml:"frameworks"`
	SecurityServices     []FingerPrintApp `json:"security_services" yaml:"security_services"`
}

func appendIfMissing(slice []FingerPrintApp, app FingerPrintApp) []FingerPrintApp {
	for _, element := range slice {
		if element.Name == app.Name {
			return slice
		}
	}
	return append(slice, app)
}

func names(apps []FingerPrintApp) []string {
	out := make([]string, len(apps))
	for i, app := range apps {
		out[i] = app.Name
	}
	return out
}

func extraFrom(data FingerPrintData) map[string]string {
	extra := map[string]string{}
	add := func(key string, apps []FingerPrintApp) {
		if len(apps) > 0 {
			extra[key] = strings.Join(names(apps), ", ")
		}
	}
	add("fingerprint_certificate_authority", data.CertificateAuthority)
	add("fingerprint_hosting", data.Hosting)
	add("fingerprint_os", data.OS)
	add("fingerprint_softwares", data.Softwares)
	add("fingerprint_databases", data.Databases)
	add("fingerprint_servers", data.Servers)
	add("fingerprint_server_extensions", data.ServerExtensions)
	add("fingerprint_auth_services", data.AuthServices)
	add("fingerprint_cdns", data.CDNs)
	add("fingerprint_caching", data.Caching)
	add("fingerprint_languages", data.Languages)
	add("fingerprint_frameworks", data.Frameworks)
	add("fingerprint_security_services", data.SecurityServices)
	return extra
}

var Check = hxcheckdef.NewCheck(Def, func(ctx context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	resources := store.Resources()
	if len(resources) == 0 {
		return harnessx.Result{Skipped: true, SkipReason: "no resources"}, nil
	}
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resources[0])
	if !ok {
		return harnessx.Result{Err: errors.New("fingerprint: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()

	attempt, err := finding.Fetch(ctx, op, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}
	if attempt.Err != nil {
		return harnessx.Result{Skipped: true, SkipReason: attempt.Err.Error()}, nil
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		return harnessx.Result{}, err
	}

	fingerprints := wappalyzerClient.FingerprintWithInfo(attempt.Response.GetHeader(), attempt.Response.GetBody().Bytes())
	data := FingerPrintData{}
	fingerPrintIdentifier := false
	for name, fp := range fingerprints {
		if len(fp.Categories) == 0 {
			continue
		}

		for _, category := range fp.Categories {
			switch category {
			case "SSL/TLS certificate authorities":
				fingerPrintIdentifier = true
				data.CertificateAuthority = appendIfMissing(data.CertificateAuthority, FingerPrintApp{Name: name})
			case "Operating systems":
				fingerPrintIdentifier = true
				data.OS = appendIfMissing(data.OS, FingerPrintApp{Name: name})
			case "Containers", "PaaS", "IaaS", "Hosting":
				fingerPrintIdentifier = true
				data.Hosting = appendIfMissing(data.Hosting, FingerPrintApp{Name: name})
			case "CMS", "Ecommerce", "Wikis", "Blogs", "LMS", "DMS", "Page builders", "Static site generator":
				fingerPrintIdentifier = true
				data.Softwares = appendIfMissing(data.Softwares, FingerPrintApp{Name: name})
			case "Databases":
				fingerPrintIdentifier = true
				data.Databases = appendIfMissing(data.Databases, FingerPrintApp{Name: name})
			case "Web servers", "Reverse proxies":
				fingerPrintIdentifier = true
				data.Servers = appendIfMissing(data.Servers, FingerPrintApp{Name: name})
			case "Web server extensions":
				fingerPrintIdentifier = true
				data.ServerExtensions = appendIfMissing(data.ServerExtensions, FingerPrintApp{Name: name})
			case "Authentication":
				fingerPrintIdentifier = true
				data.AuthServices = appendIfMissing(data.AuthServices, FingerPrintApp{Name: name})
			case "CDN":
				fingerPrintIdentifier = true
				data.CDNs = appendIfMissing(data.CDNs, FingerPrintApp{Name: name})
			case "Caching":
				fingerPrintIdentifier = true
				data.Caching = appendIfMissing(data.Caching, FingerPrintApp{Name: name})
			case "JavaScript frameworks", "Web frameworks":
				fingerPrintIdentifier = true
				data.Frameworks = appendIfMissing(data.Frameworks, FingerPrintApp{Name: name})
			case "Programming languages":
				fingerPrintIdentifier = true
				data.Languages = appendIfMissing(data.Languages, FingerPrintApp{Name: name})
			case "Security":
				fingerPrintIdentifier = true
				data.SecurityServices = appendIfMissing(data.SecurityServices, FingerPrintApp{Name: name})
			}
		}
	}

	if !fingerPrintIdentifier {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Data: &finding.Finding{
		Operation: op,
		Attempt:   attempt,
		Extra:     extraFrom(data),
		Data:      data,
	}}, nil
})
