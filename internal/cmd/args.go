package cmd

import (
	"github.com/cerberauth/cobracurl"
	jwtcheckbase "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/spf13/cobra"
)

var (
	includeScans []string
	excludeScans []string

	noProgress              bool
	severityThreshold       float64
	onlyScansAboveThreshold bool
)

func AddCommonArgs(cmd *cobra.Command) {
	cobracurl.RegisterClientFlags(cmd.Flags())
	cobracurl.RegisterHeaderFlags(cmd.Flags())
	cobracurl.RegisterAuthFlags(cmd.Flags())
	cobracurl.RegisterRateFlag(cmd.Flags())

	cmd.Flags().StringP("rate-limit", "r", "", "Rate limit for requests (e.g. 10/s, 1/m)")
	if err := cmd.Flags().MarkDeprecated("rate-limit", "use --rate instead"); err != nil {
		panic(err)
	}

	cmd.Flags().StringArrayVarP(&includeScans, "scans", "", includeScans, "Include specific scans")
	cmd.Flags().StringArrayVar(&excludeScans, "exclude-scans", excludeScans, "Exclude specific scans")

	AddJWTSecretFlag(cmd)

	cobrareportx.RegisterFormatFlags(cmd)
	cobrareportx.RegisterTransportFlags(cmd)

	cmd.Flags().BoolVarP(&noProgress, "no-progress", "", false, "Disable progress output")
	cmd.Flags().Float64VarP(&severityThreshold, "severity-threshold", "", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")
	cmd.Flags().BoolVarP(&onlyScansAboveThreshold, "only-scans-above-threshold", "", false, "Only run checks that could reach --severity-threshold; exits on any finding since all of them do")
}

// AddJWTSecretFlag registers --jwt-secret, a known HMAC secret used to re-sign
// mutated JWTs so checks like jwt.fuzz reach servers that verify signatures.
func AddJWTSecretFlag(cmd *cobra.Command) {
	cmd.Flags().String("jwt-secret", "", "Known HMAC secret of the JWT under test, used to re-sign mutated tokens (e.g. for jwt.fuzz)")
}

// ApplyJWTSecretFlag forwards --jwt-secret to the JWT checks.
func ApplyJWTSecretFlag(cmd *cobra.Command) {
	secret, _ := cmd.Flags().GetString("jwt-secret")
	jwtcheckbase.SetKnownHMACSecret(secret)
}

func FilterScans(scans []string) []string {
	var filtered []string
	for _, s := range scans {
		if s != "" {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func GetIncludeScans() []string {
	return FilterScans(includeScans)
}

func GetExcludeScans() []string {
	return FilterScans(excludeScans)
}

func GetNoProgress() bool {
	return noProgress
}

func GetSeverityThreshold() float64 {
	return severityThreshold
}

func SetSeverityThreshold(t float64) {
	severityThreshold = t
}

func GetOnlyScansAboveThreshold() bool {
	return onlyScansAboveThreshold
}

func SetOnlyScansAboveThreshold(b bool) {
	onlyScansAboveThreshold = b
}

// GetMinSeverity returns a *float64 set to GetSeverityThreshold() when
// GetOnlyScansAboveThreshold() is true, for use as scan.ScanOptions.MinSeverity;
// nil otherwise (no severity-based check filtering).
func GetMinSeverity() *float64 {
	if !onlyScansAboveThreshold {
		return nil
	}
	t := severityThreshold
	return &t
}

func ClearValues() {
	includeScans = []string{}
	excludeScans = []string{}
	noProgress = false
	severityThreshold = 1
	onlyScansAboveThreshold = false
}
