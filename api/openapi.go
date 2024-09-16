package api

import (
	"encoding/json"
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/analyticsx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type NewOpenAPIScanRequest struct {
	Schema          string `json:"schema" binding:"required"`
	SecuritySchemes map[string]struct {
		Value string `json:"value" binding:"required"`
	} `json:"security_schemes"`

	Opts *ScanOptions `json:"options"`
}

var serverApiOpenAPITracer = otel.Tracer("server/api/openapi")

func (h *Handler) ScanOpenAPI(ctx *gin.Context) {
	var form NewOpenAPIScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	openapi, err := openapi.LoadFromData(ctx, []byte(form.Schema))
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := openapi.Validate(ctx); err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	analyticsx.TrackEvent(ctx, serverApiOpenAPITracer, "Scan OpenAPI", []attribute.KeyValue{})
	opts := parseScanOptions(form.Opts)
	opts.Header = ctx.Request.Header
	opts.Cookies = ctx.Request.Cookies()
	client := request.NewClient(opts)

	values := make(map[string]interface{}, len(form.SecuritySchemes))
	if form.SecuritySchemes != nil {
		for key, value := range form.SecuritySchemes {
			values[key] = &value.Value
		}
	}
	securitySchemesValues := auth.NewSecuritySchemeValues(values)
	s, err := scenario.NewOpenAPIScan(openapi, securitySchemesValues, client, nil)
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {}, form.Opts.Scans, form.Opts.ExcludeScans)
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if reporter.HasVulnerability() {
		analyticsx.TrackEvent(ctx, serverApiOpenAPITracer, "Vulnerability Found", nil)
	}

	response := HTTPResponseReports{
		Reports: reporter.GetReports(),
	}
	_, err = json.Marshal(response)
	if err != nil {
		analyticsx.TrackError(ctx, serverApiOpenAPITracer, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}
