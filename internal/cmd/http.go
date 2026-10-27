package cmd

import (
	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/spf13/cobra"
)

// VersionAnnotation is the root command annotation holding the vulnapi
// version, used in the default User-Agent.
const VersionAnnotation = "version"

// UserAgent returns the default User-Agent for requests sent by cmd.
func UserAgent(cmd *cobra.Command) string {
	if version := cmd.Root().Annotations[VersionAnnotation]; version != "" {
		return request.DefaultUserAgent + "/" + version
	}
	return request.DefaultUserAgent
}

func NewHTTPClientFromCmd(cmd *cobra.Command) (*request.Client, error) {
	httpClient, err := cobracurl.BuildClient(cmd)
	if err != nil {
		return nil, err
	}

	// Deprecated: --rate-limit is deprecated in favour of cobracurl's --rate flag.
	// Forward the value so existing usages keep working.
	if cmd.Flags().Changed("rate-limit") {
		rateLimit, _ := cmd.Flags().GetString("rate-limit")
		_ = cmd.Flags().Set("rate", rateLimit)
	}

	limiter, err := cobracurl.BuildRateLimiter(cmd)
	if err != nil {
		return nil, err
	}

	return request.NewClientFromHTTPClient(httpClient, limiter).WithUserAgent(UserAgent(cmd)), nil
}
