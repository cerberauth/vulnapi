package api

import (
	"net/http"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type NewURLScanRequest struct {
	URL     string `form:"url" json:"url" binding:"required"`
	Method  string `form:"method" json:"method" binding:"required"`
	Headers []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `form:"headers" json:"headers"`
	Cookies []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `form:"cookies" json:"cookies"`
}

var serverApiUrlTracer = otel.Tracer("server/api/url")

func (h *Handler) ScanURL(ctx *gin.Context) {
	var form NewURLScanRequest
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

	analyticsx.TrackEvent(ctx, serverApiUrlTracer, "Scan URL", []attribute.KeyValue{
		attribute.String("method", form.Method),
	})
	s, err := scan.NewURLScan(form.Method, form.URL, httpHeaders, httpCookies, nil)
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
