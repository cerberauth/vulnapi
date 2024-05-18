package report

type OWASP string

const (
	OWASP_2023_BOLA                            OWASP = "API1:2023 Broken Object Level Authorization"
	OWASP_2023_BrokenAuthentication            OWASP = "API2:2023 Broken Authentication"
	OWASP_2023_BOPL                            OWASP = "API3:2023 Broken Object Property Level Authorization"
	OWASP_2023_UnrestrictedResourceConsumption OWASP = "API4:2023 Unrestricted Resource Consumption"
	OWASP_2023_BFLA                            OWASP = "API5:2023 Broken Function Level Authorization"
	OWASP_2023_UnrestrictedAccessBusiness      OWASP = "API6:2023 Unrestricted Access to Sensitive Business Flows"
	OWASP_2023_SSRF                            OWASP = "API7:2023 Server Side Request Forgery"
	OWASP_2023_SecurityMisconfiguration        OWASP = "API8:2023 Security Misconfiguration"
	OWASP_2023_ImproperInventory               OWASP = "API9:2023 Improper Inventory Management"
	OWASP_2023_UnsafeConsumption               OWASP = "API10:2023 Unsafe Consumption of APIs"
)
