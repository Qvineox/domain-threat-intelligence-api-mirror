package rest

import (
	"domain_threat_intelligence_api/api/rest/routing"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"time"
)

// CreateRouter initializes application routing and all route groups
//
//	@title			Domain Threat Intelligence API
//	@version		0.0.3
//	@description	API provided by DTI project
//	@contact.name	Yaroslav Lysak
//	@contact.url	https://t.me/Qvineox
//	@host			localhost:7090
//	@BasePath		/api/v1
func CreateRouter(services Services, allowedOrigins []string) *gin.Engine {
	router := gin.Default()

	router.MaxMultipartMemory = 16 << 25

	configureCORS(router, allowedOrigins)

	baseRouteV1 := router.Group("/api/v1")

	// API groups
	routing.NewBlacklistsRouter(services.BlacklistService, baseRouteV1)
	routing.NewSystemStateRouter(services.SystemStateService, baseRouteV1)
	routing.NewServiceDeskRouter(services.ServiceDeskService, baseRouteV1)

	return router
}

func configureCORS(router *gin.Engine, allowedOrigins []string) {
	router.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"OPTIONS", "GET", "PUT", "PATCH", "DELETE", "POST"},
		AllowHeaders:     []string{"Origin", "Accept", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
}
