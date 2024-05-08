package api

import (
	"net/http"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type NewGraphQLScanRequest struct {
	Endpoint string `form:"endpoint" json:"endpoint" binding:"required"`
	Headers  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `form:"headers" json:"headers"`
	Cookies []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `form:"cookies" json:"cookies"`
}

var serverApiGraphQLTracer = otel.Tracer("server/api/graphql")

func (h *Handler) ScanGraphQL(ctx *gin.Context) {
	var form NewGraphQLScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpHeaders := make(http.Header)
	for _, header := range form.Headers {
		httpHeaders.Add(header.Name, header.Value)
	}

	httpCookies := make([]*http.Cookie, 0)
	for _, cookie := range form.Cookies {
		httpCookies = append(httpCookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}

	analyticsx.TrackEvent(ctx, serverApiGraphQLTracer, "Scan GraphQL", []attribute.KeyValue{})
	s, err := scan.NewGraphQLScan(form.Endpoint, httpHeaders, httpCookies, nil)
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
