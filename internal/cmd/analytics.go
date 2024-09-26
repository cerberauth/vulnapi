package cmd

import (
	"context"

	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/x/analyticsx"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TrackScanReport(ctx context.Context, tracer trace.Tracer, reporter *report.Reporter) {
	analyticsx.TrackEvent(ctx, tracer, "Scan Report", []attribute.KeyValue{
		attribute.Int("vulnerabilityCount", len(reporter.GetVulnerabilityReports())),
		attribute.Bool("hasVulnerability", reporter.HasVulnerability()),
		attribute.Bool("hasHighRiskSeverityVulnerability", reporter.HasHighRiskOrHigherSeverityVulnerability()),
	})
}
