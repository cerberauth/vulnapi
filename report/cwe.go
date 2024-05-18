package report

type CWE string

const (
	CWE_16_Configuration CWE = "CWE-16: Configuration"

	CWE_345_Insufficient_Verification_Authenticity   CWE = "CWE-345: Insufficient Verification of Data Authenticity"
	CWE_489_Active_Debug_Code                        CWE = "CWE-489: Active Debug Code"
	CWE_613_Insufficient_Session_Expiration          CWE = "CWE-613: Insufficient Session Expiration"
	CWE_614_Sensitive_Cookie_Without_Secure_Flag     CWE = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
	CWE_942_Overly_Permissive_CORS_Policy            CWE = "CWE-942: Permissive Cross-domain Policy with Untrusted Domains"
	CWE_1004_Sensitive_Cookie_Without_Http_Only      CWE = "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
	CWE_1021_Improper_Restriction_Rendered_UI        CWE = "CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
	CWE_1275_Sensitive_Cookie_With_Improper_SameSite CWE = "CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
)
