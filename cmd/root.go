package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cerberauth/vulnapi/cmd/discover"
	"github.com/cerberauth/vulnapi/cmd/jwt"
	"github.com/cerberauth/vulnapi/cmd/scan"
	"github.com/cerberauth/vulnapi/cmd/serve"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/x/telemetryx"
)

// argvioAPIKey is vulnapi's public_ingest-scoped Argvio API key, selecting the
// "vulnapi" tenant its usage analytics land in. It is not committed: the release
// build injects it with -ldflags -X from the ARGVIO_API_KEY secret, and a build
// without one reports nothing.
var argvioAPIKey string

var (
	sqaOptOut    bool
	otelShutdown func(context.Context) error
)

var name = "vulnapi"

func NewRootCmd(projectVersion, commit, date string) (cmd *cobra.Command) {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of this application",
		Long:  "Print the version, commit and build date of this application",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(projectVersion + " (commit=" + commit + ", built=" + date + ")")
		},
	}

	rootCmd := &cobra.Command{
		Use:     name,
		Version: projectVersion + " (commit=" + commit + ", built=" + date + ")",
		Short:   name,
		Annotations: map[string]string{
			internalCmd.VersionAnnotation: projectVersion,
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				otelShutdown, _ = telemetryx.New(cmd.Context(), name, projectVersion, telemetryx.WithCommit(commit), telemetryx.WithBuildDate(date))
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if otelShutdown != nil {
				_ = otelShutdown(cmd.Context())
				otelShutdown = nil
			}
		},
	}
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(discover.NewDiscoverCmd())
	rootCmd.AddCommand(scan.NewScanCmd())
	rootCmd.AddCommand(jwt.NewJWTCmd())
	rootCmd.AddCommand(serve.NewServeCmd())

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

func Execute(projectVersion, commit, date string) {
	c := NewRootCmd(projectVersion, commit, date)
	argvioShutdown := telemetryx.Instrument(c, projectVersion, argvioAPIKey)
	defer func() {
		_ = argvioShutdown(context.Background())
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}
	}()

	if err := telemetryx.Execute(c); err != nil {
		_ = argvioShutdown(context.Background())
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}

		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		// nolint: gocritic // false positive
		os.Exit(1)
	}
}
