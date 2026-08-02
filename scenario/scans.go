package scenario

import (
	"github.com/cerberauth/vulnapi/scan"
	authenticationbypass "github.com/cerberauth/vulnapi/scan/broken_authentication/authentication_bypass"
	jwtscan "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt"
	acceptunauthenticated "github.com/cerberauth/vulnapi/scan/discover/accept_unauthenticated"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	httpcookiesfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_fetch"
	httpcookiesnothttponly "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_not_http_only"
	httpcookiesnotsecure "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_not_secure"
	httpcookiessamesitenone "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_same_site_none"
	httpcookieswithoutexpires "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_without_expires"
	httpcookieswithoutsamesite "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_without_same_site"
	httpheaderscontentoptionsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_content_options_missing"
	httpheaderscorsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_cors_missing"
	httpheaderscorswildcard "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_cors_wildcard"
	httpheaderscspframeancestorsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_csp_frame_ancestors_missing"
	httpheaderscspmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_csp_missing"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
	httpheadersframeoptionsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_frame_options_missing"
	httpheadershstsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_hsts_missing"
	httpmethodoverride "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override"
	httpmethodoverrideauthbypass "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override_auth_bypass"
	httptrace "github.com/cerberauth/vulnapi/scan/misconfiguration/http_trace"
	httptrack "github.com/cerberauth/vulnapi/scan/misconfiguration/http_track"
)

func WithAllCommonScans(s *scan.Scan) *scan.Scan {
	s.AddCheck(fingerprint.Check, &fingerprint.Def)

	s.AddCheck(acceptunauthenticated.Check, &acceptunauthenticated.Def)
	s.AddCheck(authenticationbypass.Check, &authenticationbypass.Def)
	jwtscan.WithJWTChecks(s)

	s.AddCheck(httpcookiesfetch.Check, nil)
	s.AddCheck(httpcookiesnothttponly.Check, &httpcookiesnothttponly.Def)
	s.AddCheck(httpcookiesnotsecure.Check, &httpcookiesnotsecure.Def)
	s.AddCheck(httpcookiessamesitenone.Check, &httpcookiessamesitenone.Def)
	s.AddCheck(httpcookieswithoutsamesite.Check, &httpcookieswithoutsamesite.Def)
	s.AddCheck(httpcookieswithoutexpires.Check, &httpcookieswithoutexpires.Def)

	s.AddCheck(httpheadersfetch.Check, nil)
	s.AddCheck(httpheaderscontentoptionsmissing.Check, &httpheaderscontentoptionsmissing.Def)
	s.AddCheck(httpheaderscorsmissing.Check, &httpheaderscorsmissing.Def)
	s.AddCheck(httpheaderscorswildcard.Check, &httpheaderscorswildcard.Def)
	s.AddCheck(httpheaderscspframeancestorsmissing.Check, &httpheaderscspframeancestorsmissing.Def)
	s.AddCheck(httpheaderscspmissing.Check, &httpheaderscspmissing.Def)
	s.AddCheck(httpheadersframeoptionsmissing.Check, &httpheadersframeoptionsmissing.Def)
	s.AddCheck(httpheadershstsmissing.Check, &httpheadershstsmissing.Def)

	s.AddCheck(httpmethodoverride.Check, &httpmethodoverride.Def)
	s.AddCheck(httpmethodoverrideauthbypass.Check, &httpmethodoverrideauthbypass.Def)
	s.AddCheck(httptrace.Check, &httptrace.Def)
	s.AddCheck(httptrack.Check, &httptrack.Def)

	return s
}
