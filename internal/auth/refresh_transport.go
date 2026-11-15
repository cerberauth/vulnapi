package auth

import (
	"net/http"
	"strings"
)

type refreshTransport struct {
	base     http.RoundTripper
	registry *CredentialRegistry
}

func (r *CredentialRegistry) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &refreshTransport{base: base, registry: r}
}

func (t *refreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	for _, credential := range t.registry.all() {
		stale, ok := credential.Current()
		if !ok || !carriesValue(req, stale) {
			continue
		}
		fresh, refreshErr := credential.Refresh(req.Context(), stale)
		if refreshErr != nil || fresh == stale {
			return resp, nil
		}
		retry, cloneErr := replaceValue(req, stale, fresh)
		if cloneErr != nil {
			return resp, nil
		}
		_ = resp.Body.Close()
		return t.base.RoundTrip(retry)
	}
	return resp, nil
}

func carriesValue(req *http.Request, value string) bool {
	if value == "" {
		return false
	}
	for _, values := range req.Header {
		for _, v := range values {
			if strings.Contains(v, value) {
				return true
			}
		}
	}
	return strings.Contains(req.URL.RawQuery, value)
}

func replaceValue(req *http.Request, stale, fresh string) (*http.Request, error) {
	retry := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, http.ErrBodyNotAllowed
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		retry.Body = body
	}
	for name, values := range retry.Header {
		for i, v := range values {
			retry.Header[name][i] = strings.ReplaceAll(v, stale, fresh)
		}
	}
	if strings.Contains(retry.URL.RawQuery, stale) {
		query := retry.URL.Query()
		for name, values := range query {
			for i, v := range values {
				if v == stale {
					query[name][i] = fresh
				}
			}
		}
		retry.URL.RawQuery = query.Encode()
	}
	return retry, nil
}
