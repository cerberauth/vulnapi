package cmd

import "github.com/spf13/cobra"

var (
	headers   []string
	cookies   []string
	rateLimit string
	proxy     string

	placeholderString string
	placeholderBool   bool
)

var defaultRateLimit = "10/s"

func AddCommonArgs(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&rateLimit, "rate-limit", "r", defaultRateLimit, "Rate limit for requests (e.g. 10/s, 1/m)")
	cmd.Flags().StringVarP(&proxy, "proxy", "p", "", "Proxy URL for requests")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Headers to include in requests")
	cmd.Flags().StringArrayVarP(&cookies, "cookie", "c", nil, "Cookies to include in requests")
}

func AddPlaceholderArgs(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&placeholderBool, "fail", "f", false, "Fail silently (no output at all) on HTTP errors")
	cmd.Flags().BoolVarP(&placeholderBool, "include", "i", false, "Include protocol headers in the output")
	cmd.Flags().BoolVarP(&placeholderBool, "remote-name", "O", false, "Write output to a file named as the remote file")
	cmd.Flags().BoolVarP(&placeholderBool, "silent", "s", false, "Run in silent mode")
	cmd.Flags().StringVarP(&placeholderString, "upload-file", "T", "", "Transfer file to target API")
	cmd.Flags().StringVarP(&placeholderString, "user", "u", "", "Specify the user name and password to use for server authentication")
	cmd.Flags().StringVarP(&placeholderString, "user-agent", "A", "", "User-Agent to send to server")
}

func GetHeaders() []string {
	return headers
}

func GetCookies() []string {
	return cookies
}

func GetRateLimit() string {
	return rateLimit
}

func GetProxy() string {
	return proxy
}
