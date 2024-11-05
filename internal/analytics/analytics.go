package analytics

import (
	"context"

	"github.com/cerberauth/x/otelx"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var tracerProvider *sdktrace.TracerProvider

func NewAnalytics(ctx context.Context, projectVersion string) (*sdktrace.TracerProvider, error) {
	var err error
	tracerProvider, err = otelx.InitTracerProvider(ctx, otelx.InitResource("vulnapi", projectVersion))
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
