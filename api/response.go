package api

import (
	"net/http"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/gin-gonic/gin"
)

const errorKey = "error"

var jsonFormatter = format.NewJSONFormatter()

func writeReport(ctx *gin.Context, r *reportx.Report) {
	data, err := jsonFormatter.Format(r)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{errorKey: err.Error()})
		return
	}
	ctx.Data(http.StatusOK, jsonFormatter.MediaType(), data)
}
