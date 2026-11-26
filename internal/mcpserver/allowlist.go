package mcpserver

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrHostNotAllowed is returned when a request targets a host that is not on
// the allow-list given at server start.
var ErrHostNotAllowed = errors.New("host is not on the allow-list")

// AllowList is the set of hosts the server may send requests to. An entry is
// a host name or IP address, optionally with a port ("localhost",
// "127.0.0.1:8080"), or a "*." prefixed domain matching its subdomains but not
// the domain itself ("*.example.com"). An entry without a port matches every
// port. An empty list allows nothing.
type AllowList struct {
	entries []allowEntry
}

type allowEntry struct {
	host     string
	port     string
	wildcard bool
}

// NewAllowList parses the allow-list entries.
func NewAllowList(entries []string) (*AllowList, error) {
	list := &AllowList{}
	for _, raw := range entries {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?#@") {
			return nil, fmt.Errorf("invalid allow-list entry %q: use a host name, not a URL", raw)
		}

		entry := allowEntry{}
		if strings.HasPrefix(raw, "*.") {
			entry.wildcard = true
			raw = strings.TrimPrefix(raw, "*.")
		}
		host, port, err := net.SplitHostPort(raw)
		if err != nil {
			host, port = strings.Trim(raw, "[]"), ""
		}
		if host == "" || strings.Contains(host, "*") {
			return nil, fmt.Errorf("invalid allow-list entry %q", raw)
		}
		entry.host, entry.port = host, port
		list.entries = append(list.entries, entry)
	}
	return list, nil
}

// Len returns the number of entries.
func (l *AllowList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// Allows reports whether host (a host name or IP, with an optional port) is on
// the list.
func (l *AllowList) Allows(hostport string) bool {
	if l == nil {
		return false
	}
	hostport = strings.ToLower(hostport)
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = strings.Trim(hostport, "[]"), ""
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}

	for _, entry := range l.entries {
		if entry.port != "" && entry.port != port {
			continue
		}
		if entry.wildcard {
			if strings.HasSuffix(host, "."+entry.host) {
				return true
			}
			continue
		}
		if host == entry.host {
			return true
		}
	}
	return false
}

// CheckURL returns ErrHostNotAllowed when the host of u is not on the list.
func (l *AllowList) CheckURL(u *url.URL) error {
	if u == nil || u.Host == "" {
		return fmt.Errorf("%w: URL has no host", ErrHostNotAllowed)
	}
	if !l.Allows(u.Host) {
		return fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Host)
	}
	return nil
}

// guardTransport refuses any request, including redirects and requests sent
// by individual checks, whose host is not on the allow-list.
type guardTransport struct {
	next  http.RoundTripper
	allow *AllowList
}

func (t *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.allow.CheckURL(req.URL); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return t.next.RoundTrip(req)
}
