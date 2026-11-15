package scan

import (
	"slices"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func configFlagsFromArgs(cmd *cobra.Command, args []string) *cobra.Command {
	flags := pflag.NewFlagSet("config", pflag.ContinueOnError)
	flags.ParseErrorsAllowlist.UnknownFlags = true
	flags.Usage = func() {}
	internalCmd.AddConfigFlags(flags)
	_ = flags.Parse(args)
	probe := &cobra.Command{}
	probe.Flags().AddFlagSet(flags)
	return probe
}

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:                "scan [type]",
		Short:              "API Scan",
		Long:               "API Scan. Without a type, scans the target of the configuration file.",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if slices.Contains(args, "-h") || slices.Contains(args, "--help") {
				return cmd.Help()
			}
			c, err := internalCmd.FindConfig(configFlagsFromArgs(cmd, args))
			if err != nil {
				return err
			}
			var kind string
			if c != nil {
				kind = c.TargetKind()
			}
			if kind == "" {
				return cmd.Help()
			}
			sub, _, err := cmd.Find([]string{kind})
			if err != nil {
				return err
			}
			sub.SetContext(cmd.Context())
			if err := sub.ParseFlags(args); err != nil {
				return err
			}
			if sub.RunE != nil {
				return sub.RunE(sub, sub.Flags().Args())
			}
			sub.Run(sub, sub.Flags().Args())
			return nil
		},
	}

	scanCmd.AddCommand(NewCURLScanCmd())
	scanCmd.AddCommand(NewOpenAPIScanCmd())
	scanCmd.AddCommand(NewGraphQLScanCmd())

	return scanCmd
}
