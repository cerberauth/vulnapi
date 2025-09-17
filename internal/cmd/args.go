package cmd

import (
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/spf13/cobra"
)

var (
	headers   []string = []string{}
	cookies   []string = []string{}
	authUser  string
	rateLimit string
	proxy     string
	insecure  bool

	includeScans []string
	excludeScans []string

	reportFormat    string
	reportTransport string
	reportFile      string
	reportURL       string

	noProgress        bool
	severityThreshold float64

	placeholderString string
	placeholderBool   bool
)

var defaultRateLimit = "10/s"

func AddCommonArgs(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&rateLimit, "rate-limit", "r", defaultRateLimit, "Rate limit for requests (e.g. 10/s, 1/m)")
	cmd.Flags().StringVarP(&proxy, "proxy", "p", "", "Proxy URL for requests")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", headers, "Headers to include in requests")
	cmd.Flags().StringArrayVarP(&cookies, "cookie", "c", cookies, "Cookies to include in requests")
	cmd.Flags().StringVarP(&authUser, "user", "u", "", "Specify the user name and password to use for server authentication")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "Allow insecure server connections when using SSL (ignore certificate verification errors)")

	cmd.Flags().StringArrayVarP(&includeScans, "scans", "", includeScans, "Include specific scans")
	cmd.Flags().StringArrayVarP(&excludeScans, "exclude-scans", "e", excludeScans, "Exclude specific scans")

	cmd.Flags().StringVarP(&reportFormat, "report-format", "", "table", "Report format (table, json, yaml)")
	cmd.Flags().StringVarP(&reportTransport, "report-transport", "", "file", "The transport to use for report (e.g. file, http)")
	cmd.Flags().StringVarP(&reportFile, "report-file", "", "", "The file to write the report to")
	cmd.Flags().StringVarP(&reportURL, "report-url", "", "", "The URL to send the report to")

	cmd.Flags().BoolVarP(&noProgress, "no-progress", "", false, "Disable progress output")
	cmd.Flags().Float64VarP(&severityThreshold, "severity-threshold", "", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")
}

func AddPlaceholderArgs(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&placeholderBool, "append", "a", false, "Append to target file when uploading")
	cmd.Flags().BoolVarP(&placeholderBool, "compressed", "C", false, "Request compressed response")
	cmd.Flags().BoolVarP(&placeholderBool, "fail", "f", false, "Fail silently (no output at all) on HTTP errors")
	// TODO: Add support for form
	cmd.Flags().BoolVarP(&placeholderBool, "form", "F", false, "Specify HTTP multipart POST data")
	cmd.Flags().BoolVarP(&placeholderBool, "head", "I", false, "Show document info only")
	cmd.Flags().BoolVarP(&placeholderBool, "get", "G", false, "Send the -d data with a HTTP GET request")
	cmd.Flags().BoolVarP(&placeholderBool, "include", "i", false, "Include protocol headers in the output")
	cmd.Flags().StringVarP(&placeholderString, "json", "j", "", "JSON data to send in the body of the request")
	cmd.Flags().BoolVarP(&placeholderBool, "location", "L", false, "Follow redirects")
	cmd.Flags().BoolVarP(&placeholderBool, "remote-name", "O", false, "Write output to a file named as the remote file")
	cmd.Flags().BoolVarP(&placeholderBool, "silent", "s", false, "Run in silent mode")
	cmd.Flags().StringVarP(&placeholderString, "upload-file", "T", "", "Transfer file to target API")
	cmd.Flags().StringVarP(&placeholderString, "user-agent", "A", "", "User-Agent to send to server")
}

func GetHeaders() []string {
	if basicCredentials := basicAuth(GetAuthUser()); basicCredentials != "" {
		headers = append(headers, "Authorization: Basic "+basicCredentials)
	}
	return headers
}

func GetCookies() []string {
	return cookies
}

func GetAuthUser() string {
	return authUser
}

func GetRateLimit() string {
	return rateLimit
}

func GetProxy() string {
	return proxy
}

func GetIncludeScans() []string {
	var filteredScans []string
	for _, scan := range includeScans {
		if scan != "" {
			filteredScans = append(filteredScans, scan)
		}
	}
	return filteredScans
}

func GetExcludeScans() []string {
	var filteredScans []string
	for _, scan := range excludeScans {
		if scan != "" {
			filteredScans = append(filteredScans, scan)
		}
	}
	return filteredScans
}

func GetReportFormat() string {
	return reportFormat
}

func GetReportTransport() string {
	return reportTransport
}

func GetNoProgress() bool {
	return noProgress
}

func GetSeverityThreshold() float64 {
	return severityThreshold
}

func GetInsecure() bool {
	return insecure
}

func basicAuth(user string) string {
	credentials := strings.Split(user, ":")
	if len(credentials) != 2 || credentials[0] == "" {
		return ""
	}
	return auth.NewHTTPBasicCredentials(credentials[0], credentials[1]).Encode()
}

func ClearValues() {
	headers = []string{}
	cookies = []string{}
	authUser = ""
	rateLimit = defaultRateLimit
	proxy = ""
	insecure = false
	includeScans = []string{}
	excludeScans = []string{}
	reportFormat = "table"
	reportTransport = "file"
	reportFile = ""
	reportURL = ""
	noProgress = false
	severityThreshold = 1
}
