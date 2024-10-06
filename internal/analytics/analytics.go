package analytics

import (
	"context"
	"time"

	"github.com/cerberauth/x/analyticsx"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var tracerProvider *sdktrace.TracerProvider

func NewAnalytics(ctx context.Context, projectVersion string) (*sdktrace.TracerProvider, error) {
	var err error
	tracerProvider, err = analyticsx.NewAnalytics(ctx, analyticsx.AppInfo{
		Name:    "vulnapi",
		Version: projectVersion,
	}, otlptracehttp.WithTimeout(time.Second*2), otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}))
	if err != nil {
		return nil, err
	}
	return tracerProvider, err
}

func Close() error {
	if tracerProvider == nil {
		return nil
	}

	return tracerProvider.Shutdown(context.Background())
}
