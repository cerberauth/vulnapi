package api

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type NewURLScanRequest struct {
	URL    string `form:"url" json:"url" binding:"required"`
	Method string `form:"method" json:"method" binding:"required"`

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
	s, err := scan.NewURLScan(form.Method, form.URL, client, nil)
	if err != nil {
		analyticsx.TrackError(ctx, serverApiUrlTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.WithAllScans()

	reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiUrlTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if reporter.HasVulnerability() {
		analyticsx.TrackEvent(ctx, serverApiUrlTracer, "Vulnerability Found", nil)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"reports": FormatReports(reporter.GetReports()),
	})
}
