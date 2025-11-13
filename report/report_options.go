package report

type ReportOptions struct {
	ScansIncluded []string `json:"scansIncluded,omitempty" yaml:"scansIncluded,omitempty"`
	ScansExcluded []string `json:"scansExcluded,omitempty" yaml:"scansExcluded,omitempty"`

	MinIssueSeverity float64  `json:"minSeverity,omitempty" yaml:"minSeverity,omitempty"`
	CWEsIncluded     []string `json:"CWEsIncluded,omitempty" yaml:"CWEsIncluded,omitempty"`
	CWEsExcluded     []string `json:"CWEsExcluded,omitempty" yaml:"CWEsExcluded,omitempty"`
	OWASPsIncluded   []string `json:"OWASPsIncluded,omitempty" yaml:"OWASPsIncluded,omitempty"`
	OWASPsExcluded   []string `json:"OWASPsExcluded,omitempty" yaml:"OWASPsExcluded,omitempty"`
}

func NewEmptyOptionsReport() *ReportOptions {
	return &ReportOptions{}
}
