package auth

import "github.com/cerberauth/harnessx/probe"

// RequestMutators turns a SecurityScheme's attack-value headers/cookies into
// probe.RequestMutators, for use with probe.NewRequest.
func RequestMutators(securityScheme *SecurityScheme) []probe.RequestMutator {
	if securityScheme == nil {
		return nil
	}

	var mutators []probe.RequestMutator
	for k, v := range securityScheme.GetHeaders() {
		if len(v) == 0 {
			continue
		}
		mutators = append(mutators, probe.WithHeader(k, v[0]))
	}
	for _, c := range securityScheme.GetCookies() {
		mutators = append(mutators, probe.WithCookie(c))
	}
	return mutators
}
