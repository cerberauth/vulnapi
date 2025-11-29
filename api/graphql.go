package api

import (
	"net/http"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/gin-gonic/gin"
)

type NewGraphQLScanRequest struct {
	Endpoint string `form:"endpoint" json:"endpoint" binding:"required"`

	Opts *ScanOptions `json:"options"`
}

func (h *Handler) ScanGraphQL(ctx *gin.Context) {
	var form NewGraphQLScanRequest
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	parsedEndpoint, err := url.Parse(form.Endpoint)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	opts := parseScanOptions(form.Opts)
	opts.Header = ctx.Request.Header
	opts.Cookies = ctx.Request.Cookies()
	client := request.NewClient(opts)

	s, err := scenario.NewGraphQLScan(parsedEndpoint, client, &scan.ScanOptions{
		IncludeScans: form.Opts.Scans,
		ExcludeScans: form.Opts.ExcludeScans,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	reporter, _, err := s.Execute(ctx, nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, HTTPResponseReports{
		Reports: reporter.GetScanReports(),
	})
}
