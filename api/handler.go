package api

import "github.com/gin-gonic/gin"

type Handler struct {
	// This is a placeholder for the actual implementation.
}

func NewHandler() *Handler {
	return &Handler{}
}

func Routes(r *gin.Engine, h *Handler) {
	scanAPI := r.Group("/scans")
	scanAPI.POST("/openapi", h.ScanOpenAPI)
	scanAPI.POST("/graphql", h.ScanGraphQL)
	scanAPI.POST("/url", h.ScanURL)
}
