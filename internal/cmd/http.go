package cmd

import (
	"time"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/spf13/cobra"
)

// DefaultHTTPTimeout is the overall request timeout applied when --max-time is not set.
const DefaultHTTPTimeout = 30 * time.Second

func NewHTTPClientFromCmd(cmd *cobra.Command) (*request.Client, error) {
	httpClient, err := cobracurl.BuildClient(cmd, cobracurl.WithDefaultTimeout(DefaultHTTPTimeout))
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

	return request.NewClientFromHTTPClient(httpClient, limiter), nil
}
