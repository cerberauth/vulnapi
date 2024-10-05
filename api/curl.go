package api

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/analyticsx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type NewURLScanRequest struct {
	URL    string `form:"url" json:"url" binding:"required"`
	Method string `form:"method" json:"method" binding:"required"`
	Data   string `form:"data" json:"data"`

	Opts *ScanOptions `json:"options"`
}

var serverApiUrlTracer = otel.Tracer("server/api/url")

func (h *Handler) ScanURL(ctx *gin.Context) {
	var form NewURLScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	analyticsx.TrackEvent(ctx, serverApiUrlTracer, "Scan URL", []attribute.KeyValue{
		attribute.String("method", form.Method),
	})

	opts := parseScanOptions(form.Opts)
	opts.Header = ctx.Request.Header
	opts.Cookies = ctx.Request.Cookies()
	client := request.NewClient(opts)
	s, err := scenario.NewURLScan(form.Method, form.URL, form.Data, client, &scan.ScanOptions{
		IncludeScans: form.Opts.Scans,
		ExcludeScans: form.Opts.ExcludeScans,
	})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiUrlTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiUrlTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if reporter.HasVulnerability() {
		analyticsx.TrackEvent(ctx, serverApiUrlTracer, "Vulnerability Found", nil)
	}

	ctx.JSON(http.StatusOK, HTTPResponseReports{
		Reports: reporter.GetReports(),
	})
}
