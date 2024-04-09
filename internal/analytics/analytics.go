package analytics

import (
	"context"

	"github.com/cerberauth/x/analyticsx"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var tracerProvider *sdktrace.TracerProvider

func NewAnalytics(ctx context.Context) (*sdktrace.TracerProvider, error) {
	var err error
	tracerProvider, err = analyticsx.NewAnalytics(ctx, analyticsx.AppInfo{
		Name: "vulnapi",
	})
	if err != nil {
		return nil, err
	}
	return tracerProvider, err
}
