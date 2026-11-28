package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cerberauth/vulnapi/config"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/spf13/cobra"
)

// ScanSettings is the effective configuration of a scan: flags override
// the selected environment of the configuration file, which overrides the
// file, which overrides the defaults.
type ScanSettings struct {
	Config *config.Config

	ToolVersion             string
	IncludeScans            []string
	ExcludeScans            []string
	ScansFromConfig         bool
	AllowUnsafeMethods      bool
	SeverityThreshold       float64
	OnlyScansAboveThreshold bool
	NoProgress              bool
	Operations              *scan.OperationFilter
}

func stringArrayFlag(cmd *cobra.Command, name string) []string {
	values, _ := cmd.Flags().GetStringArray(name)
	return FilterScans(values)
}

func ResolveScanSettings(cmd *cobra.Command) (*ScanSettings, error) {
	cfg, err := LoadConfig(cmd)
	if err != nil {
		return nil, err
	}
	flags := cmd.Flags()
	s := &ScanSettings{Config: cfg, ToolVersion: Version(cmd)}
	s.IncludeScans = stringArrayFlag(cmd, "scans")
	s.ExcludeScans = stringArrayFlag(cmd, "exclude-scans")
	s.AllowUnsafeMethods, _ = flags.GetBool("allow-unsafe-methods")
	s.SeverityThreshold, _ = flags.GetFloat64("severity-threshold")
	s.OnlyScansAboveThreshold, _ = flags.GetBool("only-scans-above-threshold")
	s.NoProgress, _ = flags.GetBool("no-progress")

	if cfg != nil {
		if err := s.applyConfig(cmd, cfg); err != nil {
			return nil, err
		}
	}

	SetSeverityThreshold(s.SeverityThreshold)
	SetOnlyScansAboveThreshold(s.OnlyScansAboveThreshold)
	return s, nil
}

func (s *ScanSettings) applyConfig(cmd *cobra.Command, cfg *config.Config) error {
	flags := cmd.Flags()
	if c := cfg.Scan; c != nil {
		if c.Checks != nil {
			if !flags.Changed("scans") && len(c.Checks.Include) > 0 {
				s.IncludeScans = c.Checks.Include
				s.ScansFromConfig = true
			}
			if !flags.Changed("exclude-scans") {
				s.ExcludeScans = c.Checks.Exclude
			}
		}
		if c.AllowUnsafeMethods != nil && !flags.Changed("allow-unsafe-methods") {
			s.AllowUnsafeMethods = *c.AllowUnsafeMethods
		}
		if o := c.Operations; o != nil {
			s.Operations = &scan.OperationFilter{Paths: o.Paths, ExcludePaths: o.ExcludePaths, Tags: o.Tags, OperationIDs: o.OperationIDs, Methods: o.Methods}
		}
		if c.Rate != "" && !flags.Changed("rate") && !flags.Changed("rate-limit") && flags.Lookup("rate") != nil {
			if err := flags.Set("rate", c.Rate); err != nil {
				return fmt.Errorf("scan.rate: %w", err)
			}
		}
		if c.Timeout != "" && !flags.Changed("max-time") && flags.Lookup("max-time") != nil {
			timeout, _ := time.ParseDuration(c.Timeout)
			if err := flags.Set("max-time", strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64)); err != nil {
				return fmt.Errorf("scan.timeout: %w", err)
			}
		}
	}
	if r := cfg.Report; r != nil && r.FailOn != "" && !flags.Changed("severity-threshold") {
		threshold, err := config.ParseFailOn(r.FailOn)
		if err != nil {
			return err
		}
		s.SeverityThreshold = threshold
	}
	return nil
}

func (s *ScanSettings) MinSeverity() *float64 {
	if !s.OnlyScansAboveThreshold {
		return nil
	}
	threshold := s.SeverityThreshold
	return &threshold
}

func (s *ScanSettings) ScanOptions() *scan.ScanOptions {
	return &scan.ScanOptions{
		ToolVersion:        s.ToolVersion,
		AllowUnsafeMethods: s.AllowUnsafeMethods,
		IncludeScans:       s.IncludeScans,
		ExcludeScans:       s.ExcludeScans,
		MinSeverity:        s.MinSeverity(),
		Operations:         s.Operations,
		SkipUnknownScans:   s.ScansFromConfig,
	}
}

// ScansFiltered reports whether the user selected the checks to run, in
// which case any finding fails the scan.
func (s *ScanSettings) ScansFiltered(cmd *cobra.Command) bool {
	return (cmd.Flags().Changed("scans") && len(s.IncludeScans) > 0) || s.OnlyScansAboveThreshold
}

func (s *ScanSettings) Target() *config.Target {
	if s == nil || s.Config == nil {
		return nil
	}
	return s.Config.Target
}

// TargetHeaders resolves the headers of the configuration file target.
// Headers set with -H take precedence.
func (s *ScanSettings) TargetHeaders(ctx context.Context, flagHeaders http.Header) (http.Header, error) {
	headers := http.Header{}
	if target := s.Target(); target != nil {
		for name, value := range target.Headers {
			if flagHeaders.Get(name) != "" {
				continue
			}
			resolved, err := value.Resolve(ctx)
			if err != nil {
				return nil, fmt.Errorf("target.headers.%s: %w", name, err)
			}
			headers.Set(name, resolved)
		}
	}
	for name, values := range flagHeaders {
		headers[name] = values
	}
	return headers, nil
}

func (s *ScanSettings) PrintUnknownScans(cmd *cobra.Command, unknown []string) {
	for _, pattern := range unknown {
		cmd.PrintErrln("Info: scan " + pattern + " of the configuration file is not available in this build and is skipped")
	}
}
