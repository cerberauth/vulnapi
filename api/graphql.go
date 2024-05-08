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
	opts := parseScanOptions(form.Opts)

	analyticsx.TrackEvent(ctx, serverApiGraphQLTracer, "Scan GraphQL", []attribute.KeyValue{})
	client := request.NewClient(request.NewClientOptions{
		Header:  ctx.Request.Header,
		Cookies: ctx.Request.Cookies(),

		Rate: opts.Rate,
	})
	s, err := scan.NewGraphQLScan(form.Endpoint, client, nil)
	if err != nil {
		analyticsx.TrackError(ctx, serverApiGraphQLTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.WithAllVulnsScans().WithAllBestPracticesScans().WithAllGraphQLScans()

	reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiGraphQLTracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if reporter.HasVulnerability() {
		analyticsx.TrackEvent(ctx, serverApiGraphQLTracer, "Vulnerability Found", nil)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"reports": FormatReports(reporter.GetReports()),
	})
}
