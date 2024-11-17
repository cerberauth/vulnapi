package auth

func GetSecuritySchemeUniqueName(securityScheme *SecurityScheme) string {
	if securityScheme == nil {
		return ""
	}

	uniqueName := string(securityScheme.GetType()) + "-" + string(securityScheme.GetScheme())
	if securityScheme.GetIn() != nil {
		uniqueName += "-" + string(*securityScheme.GetIn())
	}

	return uniqueName
}
