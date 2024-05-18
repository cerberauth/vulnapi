package report

type Classifications struct {
	OWASP OWASP `json:"owasp,omitempty" yaml:"owasp,omitempty"`
	CWE   CWE   `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	CAPEC CAPEC `json:"capec,omitempty" yaml:"capec,omitempty"`
}

type CVSS struct {
	Version float64 `json:"version" yaml:"version"`
	Vector  string  `json:"vector" yaml:"vector"`
	Score   float64 `json:"score" yaml:"score"`
}

type Issue struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
	CVSS CVSS   `json:"cvss" yaml:"cvss"`

	Classifications *Classifications `json:"classifications,omitempty" yaml:"classifications,omitempty"`
}
