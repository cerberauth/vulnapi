package scenario

import (
	"github.com/cerberauth/vulnapi/scan"
	authenticationbypass "github.com/cerberauth/vulnapi/scan/broken_authentication/authentication_bypass"
	jwtalgnone "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/alg_none"
	jwtblanksecret "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/blank_secret"
	jwtcheckbase "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	jwtfuzz "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/fuzz"
	jwthmacconfusion "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/hmac_confusion"
	jwtjkuinjection "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/jku_injection"
	jwtjwkinjection "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/jwk_injection"
	jwtkidpathtraversal "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/kid_path_traversal"
	jwtkidsqlinjection "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/kid_sql_injection"
	jwtnoverification "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/no_verification"
	jwtnullsignature "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/null_signature"
	jwtpsychicsignature "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/psychic_signature"
	jwtweaksecret "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/weak_secret"
	jwtx5cinjection "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/x5c_injection"
	jwtx5uinjection "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/x5u_injection"
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

	s.AddCheck(jwtcheckbase.ProbeCtxCheck, nil)
	s.AddCheck(jwtcheckbase.BaselineCheck, nil)
	s.AddCheck(jwtnoverification.Check, &jwtnoverification.Def)
	s.AddCheck(jwtalgnone.Check, &jwtalgnone.Def)
	s.AddCheck(jwtblanksecret.Check, &jwtblanksecret.Def)
	s.AddCheck(jwtnullsignature.Check, &jwtnullsignature.Def)
	s.AddCheck(jwthmacconfusion.Check, &jwthmacconfusion.Def)
	s.AddCheck(jwtpsychicsignature.Check, &jwtpsychicsignature.Def)
	s.AddCheck(jwtkidsqlinjection.Check, &jwtkidsqlinjection.Def)
	s.AddCheck(jwtkidpathtraversal.Check, &jwtkidpathtraversal.Def)
	s.AddCheck(jwtjwkinjection.Check, &jwtjwkinjection.Def)
	s.AddCheck(jwtjkuinjection.Check, &jwtjkuinjection.Def)
	s.AddCheck(jwtx5cinjection.Check, &jwtx5cinjection.Def)
	s.AddCheck(jwtx5uinjection.Check, &jwtx5uinjection.Def)
	s.AddCheck(jwtweaksecret.Check, &jwtweaksecret.Def)
	s.AddCheck(jwtfuzz.Check, &jwtfuzz.Def)

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
