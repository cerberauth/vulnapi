package api

import (
	"encoding/json"
	"net/http"

	"github.com/cerberauth/vulnapi/internal/analytics"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

type NewOpenAPIScanRequest struct {
	Schema          string `json:"schema" binding:"required"`
	SecuritySchemes map[string]struct {
		Value string `json:"value" binding:"required"`
	} `json:"securitySchemes"`

	Opts *ScanOptions `json:"options"`
}

func (h *Handler) ScanOpenAPI(ctx *gin.Context) {
	var form NewOpenAPIScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	traceCtx, span := tracer.Start(ctx, "Scan OpenAPI")
	defer span.End()

	doc, err := openapi.LoadFromData(traceCtx, []byte(form.Schema))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := doc.Validate(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

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
	securitySchemesValues := openapi.NewSecuritySchemeValues(values)
	s, err := scenario.NewOpenAPIScan(doc, securitySchemesValues, client, nil, &scan.ScanOptions{
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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	analytics.TrackScanReport(traceCtx, reporter)

	response := HTTPResponseReports{
		Reports: reporter.GetScanReports(),
	}
	_, err = json.Marshal(response)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}
