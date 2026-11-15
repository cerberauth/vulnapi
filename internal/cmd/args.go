package cmd

import (
	"github.com/cerberauth/cobracurl"
	jwtcrackcheckbase "github.com/cerberauth/jwtop/jwt/crack/checkbase"
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
	allowUnsafeMethods      bool
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

	AddJWTFlags(cmd)

	cobrareportx.RegisterFormatFlags(cmd)
	cobrareportx.RegisterTransportFlags(cmd)

	cmd.Flags().BoolVarP(&noProgress, "no-progress", "", false, "Disable progress output")
	cmd.Flags().Float64VarP(&severityThreshold, "severity-threshold", "", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")
	cmd.Flags().BoolVarP(&onlyScansAboveThreshold, "only-scans-above-threshold", "", false, "Only run checks that could reach --severity-threshold; exits on any finding since all of them do")
	RegisterAllowUnsafeMethodsFlag(cmd, &allowUnsafeMethods)
}

func AddJWTFlags(cmd *cobra.Command) {
	cmd.Flags().String("jwt-secret", "", "Known HMAC secret of the JWT under test, used to re-sign mutated tokens (e.g. for jwt.fuzz)")
	cmd.Flags().String("jwt-other-audience-token", "", "Validly signed JWT issued for another audience, sent by jwt.audience_not_validated")
	cmd.Flags().String("jwt-other-issuer-token", "", "Validly signed JWT issued by another issuer of the same identity provider, sent by jwt.issuer_not_validated")
	cmd.Flags().Duration("jwt-max-lifetime", jwtcrackcheckbase.DefaultMaxTokenLifetime, "JWT lifetime above which jwt.long_lifetime reports the token")
}

func ApplyJWTFlags(cmd *cobra.Command) {
	secret, _ := cmd.Flags().GetString("jwt-secret")
	otherAudienceToken, _ := cmd.Flags().GetString("jwt-other-audience-token")
	otherIssuerToken, _ := cmd.Flags().GetString("jwt-other-issuer-token")
	maxLifetime, _ := cmd.Flags().GetDuration("jwt-max-lifetime")
	jwtcheckbase.SetOptions(jwtcheckbase.Options{
		HMACSecret:         secret,
		OtherAudienceToken: otherAudienceToken,
		OtherIssuerToken:   otherIssuerToken,
		MaxTokenLifetime:   maxLifetime,
	})
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

// RegisterAllowUnsafeMethodsFlag registers --allow-unsafe-methods on cmd.
func RegisterAllowUnsafeMethodsFlag(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVar(p, "allow-unsafe-methods", false, "Allow checks to send unsafe HTTP methods (POST, PUT, PATCH, DELETE) with valid credentials")
}

func GetAllowUnsafeMethods() bool {
	return allowUnsafeMethods
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
