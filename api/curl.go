package api

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/analytics"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

type NewURLScanRequest struct {
	URL    string `form:"url" json:"url" binding:"required"`
	Method string `form:"method" json:"method" binding:"required"`
	Data   string `form:"data" json:"data"`

	Opts *ScanOptions `json:"options"`
}

func (h *Handler) ScanURL(ctx *gin.Context) {
	var form NewURLScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	traceCtx, span := tracer.Start(ctx.Request.Context(), "Scan URL")
	defer span.End()

	opts := parseScanOptions(form.Opts)
	opts.Header = ctx.Request.Header
	opts.Cookies = ctx.Request.Cookies()
	client := request.NewClient(opts)

	s, err := scenario.NewURLScan(form.Method, form.URL, form.Data, client, nil, &scan.ScanOptions{
		IncludeScans:     form.Opts.Scans,
		ExcludeScans:     form.Opts.ExcludeScans,
		MinIssueSeverity: form.Opts.MinSeverity,
		IncludeCWEs:      form.Opts.IncludeCWEs,
		ExcludeCWEs:      form.Opts.ExcludeCWEs,
		IncludeOWASPs:    form.Opts.IncludeOWASPs,
		ExcludeOWASPs:    form.Opts.ExcludeOWASPs,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	reporter, _, err := s.Execute(traceCtx, nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	analytics.TrackScanReport(traceCtx, reporter)

	ctx.JSON(http.StatusOK, HTTPResponseReports{
		Reports: reporter.GetScanReports(),
	})
}
