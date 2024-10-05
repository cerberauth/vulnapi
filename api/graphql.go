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

type NewGraphQLScanRequest struct {
	Endpoint string `form:"endpoint" json:"endpoint" binding:"required"`

	Opts *ScanOptions `json:"options"`
}

var serverApiGraphQLTracer = otel.Tracer("server/api/graphql")

func (h *Handler) ScanGraphQL(ctx *gin.Context) {
	var form NewGraphQLScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analyticsx.TrackEvent(ctx, serverApiGraphQLTracer, "Scan GraphQL", []attribute.KeyValue{})
	opts := parseScanOptions(form.Opts)
	opts.Header = ctx.Request.Header
	opts.Cookies = ctx.Request.Cookies()
	client := request.NewClient(opts)
	s, err := scenario.NewGraphQLScan(form.Endpoint, client, &scan.ScanOptions{
		IncludeScans: form.Opts.Scans,
		ExcludeScans: form.Opts.ExcludeScans,
	})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiGraphQLTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiGraphQLTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if reporter.HasVulnerability() {
		analyticsx.TrackEvent(ctx, serverApiGraphQLTracer, "Vulnerability Found", nil)
	}

	ctx.JSON(http.StatusOK, HTTPResponseReports{
		Reports: reporter.GetReports(),
	})
}
