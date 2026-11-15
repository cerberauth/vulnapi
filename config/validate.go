package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/reportx/format"
)

var severityNames = map[string]float64{
	"info":     0,
	"low":      0.1,
	"medium":   4,
	"high":     7,
	"critical": 9,
}

// ParseFailOn converts a report.failOn value, a severity name or a CVSS
// score, to the minimum CVSS score that fails the scan.
func ParseFailOn(value string) (float64, error) {
	if score, ok := severityNames[strings.ToLower(value)]; ok {
		return score, nil
	}
	score, err := strconv.ParseFloat(value, 64)
	if err != nil || score < 0 || score > 10 {
		return 0, fmt.Errorf("invalid failOn %q: use info, low, medium, high, critical or a CVSS score between 0 and 10", value)
	}
	return score, nil
}

type validationErrors []string

func (v *validationErrors) add(field string, err error) {
	if err != nil {
		*v = append(*v, fmt.Sprintf("%s: %v", field, err))
	}
}

func (v validationErrors) err() error {
	if len(v) == 0 {
		return nil
	}
	return errors.New(strings.Join(v, "\n"))
}

func (c *Config) Validate() error {
	var errs validationErrors
	if c.Version == 0 {
		errs.add("version", errors.New("required"))
	} else if c.Version != CurrentVersion {
		errs.add("version", fmt.Errorf("unsupported version %d, this build reads version %d", c.Version, CurrentVersion))
	}
	c.Target.validate("target", &errs)
	validateIdentities("identities", c.Identities, &errs)
	c.Scan.validate("scan", &errs)
	c.Report.validate("report", &errs)
	for i, suppression := range c.Suppressions {
		suppression.validate(fmt.Sprintf("suppressions[%d]", i), &errs)
	}
	for _, name := range sortedKeys(c.Environments) {
		environment := c.Environments[name]
		field := "environments." + name
		environment.Target.validate(field+".target", &errs)
		validateIdentities(field+".identities", environment.Identities, &errs)
		environment.Scan.validate(field+".scan", &errs)
		environment.Report.validate(field+".report", &errs)
	}
	return errs.err()
}

func validateAbsoluteURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", value)
	}
	return nil
}

func (t *Target) validate(field string, errs *validationErrors) {
	if t == nil {
		return
	}
	kinds := 0
	for _, set := range []bool{t.OpenAPI != "", t.GraphQL != "", t.Request != nil} {
		if set {
			kinds++
		}
	}
	if kinds > 1 {
		errs.add(field, errors.New("set only one of openapi, graphql or request"))
	}
	if t.Server != "" {
		errs.add(field+".server", validateAbsoluteURL(t.Server))
		if t.OpenAPI == "" && kinds > 0 {
			errs.add(field+".server", errors.New("only applies to an openapi target"))
		}
	}
	if t.GraphQL != "" {
		errs.add(field+".graphql", validateAbsoluteURL(t.GraphQL))
	}
	if t.Request != nil {
		errs.add(field+".request.url", validateAbsoluteURL(t.Request.URL))
	}
	for _, name := range sortedKeys(t.Headers) {
		errs.add(field+".headers."+name, t.Headers[name].validate())
	}
}

func validateIdentities(field string, identities map[string]Identity, errs *validationErrors) {
	for _, name := range sortedKeys(identities) {
		identity := identities[name]
		identityField := field + "." + name
		if len(identity.Schemes) == 0 {
			errs.add(identityField+".schemes", errors.New("at least one security scheme is required"))
		}
		for _, schemeName := range sortedKeys(identity.Schemes) {
			identity.Schemes[schemeName].validate(identityField+".schemes."+schemeName, errs)
		}
	}
}

func (c Credential) validate(field string, errs *validationErrors) {
	if c.literal {
		errs.add(field, ErrLiteralSecret)
		return
	}
	if c.OAuth2 == nil {
		errs.add(field, c.SecretRef.validate())
		return
	}
	if c.count() > 0 {
		errs.add(field, errors.New("set either a secret reference or oauth2, not both"))
	}
	o := c.OAuth2
	if o.TokenURL != "" {
		errs.add(field+".oauth2.tokenUrl", validateAbsoluteURL(o.TokenURL))
	}
	if o.ClientID == nil {
		errs.add(field+".oauth2.clientId", errors.New("required"))
	}
	if (o.Username == nil) != (o.Password == nil) {
		errs.add(field+".oauth2", errors.New("username and password must be set together"))
	}
	for name, ref := range map[string]*SecretRef{"clientId": o.ClientID, "clientSecret": o.ClientSecret, "username": o.Username, "password": o.Password} {
		if ref != nil {
			errs.add(field+".oauth2."+name, ref.validate())
		}
	}
}

func (s *Scan) validate(field string, errs *validationErrors) {
	if s == nil {
		return
	}
	if s.Checks != nil {
		for i, pattern := range append(slices.Clone(s.Checks.Include), s.Checks.Exclude...) {
			if _, err := path.Match(pattern, ""); err != nil || pattern == "" {
				errs.add(fmt.Sprintf("%s.checks[%d]", field, i), fmt.Errorf("invalid check pattern %q", pattern))
			}
		}
	}
	if s.Operations != nil {
		for _, method := range s.Operations.Methods {
			if !slices.Contains(httpMethods, strings.ToUpper(method)) {
				errs.add(field+".operations.methods", fmt.Errorf("unknown HTTP method %q", method))
			}
		}
	}
	if s.Timeout != "" {
		if d, err := time.ParseDuration(s.Timeout); err != nil || d <= 0 {
			errs.add(field+".timeout", fmt.Errorf("invalid duration %q", s.Timeout))
		}
	}
	if s.Rate != "" {
		errs.add(field+".rate", validateRate(s.Rate))
	}
}

var httpMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect}

func validateRate(rate string) error {
	count, unit, ok := strings.Cut(rate, "/")
	n, err := strconv.ParseFloat(count, 64)
	if !ok || err != nil || n <= 0 || !slices.Contains([]string{"s", "m", "h"}, unit) {
		return fmt.Errorf("invalid rate %q, expected <requests>/<s|m|h>", rate)
	}
	return nil
}

func validFormat(name string) bool {
	if slices.Contains([]string{"yml", "text", "plain"}, name) {
		return true
	}
	for _, f := range format.FormatNames {
		if string(f) == name {
			return true
		}
	}
	return false
}

func (r *Report) validate(field string, errs *validationErrors) {
	if r == nil {
		return
	}
	if r.FailOn != "" {
		_, err := ParseFailOn(r.FailOn)
		errs.add(field+".failOn", err)
	}
	for i, output := range r.Outputs {
		outputField := fmt.Sprintf("%s.outputs[%d]", field, i)
		if !validFormat(output.Format) {
			errs.add(outputField+".format", fmt.Errorf("unknown format %q", output.Format))
		}
		if output.Path == "" {
			errs.add(outputField+".path", errors.New("required"))
		}
	}
	if r.URL != "" {
		errs.add(field+".url", validateAbsoluteURL(r.URL))
	}
	if r.Format != "" && !validFormat(r.Format) {
		errs.add(field+".format", fmt.Errorf("unknown format %q", r.Format))
	}
	for _, name := range sortedKeys(r.Headers) {
		errs.add(field+".headers."+name, r.Headers[name].validate())
	}
}

func (s Suppression) validate(field string, errs *validationErrors) {
	if s.Check == "" {
		errs.add(field+".check", errors.New("required"))
	}
	if strings.TrimSpace(s.Reason) == "" {
		errs.add(field+".reason", errors.New("required"))
	}
	if s.Expires.IsZero() {
		errs.add(field+".expires", errors.New("required"))
	}
}
