package serve

import (
	"log"

	"github.com/cerberauth/vulnapi/api"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

var (
	port string
)

func NewServeCmd() (serveCmd *cobra.Command) {
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the server",
		Run: func(cmd *cobra.Command, args []string) {
			r := gin.New()
			r.Use(gin.Recovery())
			r.Use(otelgin.Middleware("giteway"))
			r.Use(requestid.New())

			handler := api.NewHandler()
			api.Routes(r, handler)

			if err := r.Run(":" + port); err != nil {
				log.Fatal(err)
			}
		},
	}

	serveCmd.Flags().StringVarP(&port, "port", "p", "8080", "Port to listen to")

	return serveCmd
}
