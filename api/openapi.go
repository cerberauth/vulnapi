package api

import (
	"net/http"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type NewOpenAPIScanRequest struct {
	Schema     string `json:"schema" binding:"required"`
	ValidToken string `json:"valid_token"`
}

var serverApiOpenAPITracer = otel.Tracer("server/api/openapi")

func (h *Handler) ScanOpenAPI(ctx *gin.Context) {
	var form NewOpenAPIScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	doc, err := openapi3.NewLoader().LoadFromData([]byte(form.Schema))
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	analyticsx.TrackEvent(ctx, serverApiOpenAPITracer, "Scan OpenAPI", []attribute.KeyValue{})
	s, err := scan.NewOpenAPIScan(doc, &form.ValidToken, nil)
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.WithAllVulnsScans().WithAllBestPracticesScans().WithAllOpenAPIDiscoverScans()

	reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {})
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if reporter.HasVulnerability() {
		analyticsx.TrackEvent(ctx, serverApiOpenAPITracer, "Vulnerability Found", nil)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"reports": FormatReports(reporter.GetReports()),
	})
}