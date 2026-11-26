package mcp

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/mcpserver"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

// NewMCPCmd returns the "mcp" command, a local Model Context Protocol server
// over stdio exposing VulnAPI scans to AI assistants.
func NewMCPCmd() (mcpCmd *cobra.Command) {
	var (
		allowHosts []string
		allowEnv   []string
		specRoot   string
		rate       int
	)

	mcpCmd = &cobra.Command{
		Use:   "mcp",
		Short: "Run a local MCP server",
		Long: "Run a Model Context Protocol server over stdio so AI assistants can run VulnAPI scans and read their findings.\n\n" +
			"Scans only reach the hosts given with --allow-host. Credentials are passed to tools as environment variable names, never as values.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			allow, err := mcpserver.NewAllowList(allowHosts)
			if err != nil {
				return err
			}
			if allow.Len() == 0 {
				return errors.New("at least one --allow-host is required: scans only start for hosts on the allow-list")
			}

			server, err := mcpserver.New(mcpserver.Options{
				AllowHosts: allow,
				Env:        mcpserver.NewEnvResolver(allowEnv),
				SpecRoot:   specRoot,
				RateLimit:  rate,
				Version:    internalCmd.Version(cmd),
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return server.Run(ctx, &sdk.StdioTransport{})
		},
	}

	mcpCmd.Flags().StringArrayVar(&allowHosts, "allow-host", nil, "Host scans may target, for example localhost, 127.0.0.1:8080 or *.example.com (repeatable, required)")
	mcpCmd.Flags().StringArrayVar(&allowEnv, "allow-env", nil, "Environment variable tools may reference besides VULNAPI_*, a trailing * matches a prefix (repeatable)")
	mcpCmd.Flags().StringVar(&specRoot, "spec-root", "", "Directory local OpenAPI documents are read from (default: the working directory)")
	mcpCmd.Flags().IntVar(&rate, "rate", 0, "Maximum requests per second sent by a scan (default: the scanner default)")

	return mcpCmd
}
