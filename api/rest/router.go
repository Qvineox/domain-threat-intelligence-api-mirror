package rest

import (
	"domain_threat_intelligence_api/api/rest/routing"
	"github.com/gin-gonic/gin"
)

// CreateRouter initializes application routing and all route groups
// @title        Domain Threat Intelligence API
// @version      0.0.2
// @description  API provided by DTI project
// @contact.name Yaroslav Lysak
// @contact.url  https://t.me/Qvineox
// @host         localhost:7090
// @BasePath     /api/v1
func CreateRouter(services Services) *gin.Engine {
	router := gin.Default()

	baseRouteV1 := router.Group("/api/v1")

	// maintenance API group
	routing.HandleMaintenanceGroup(baseRouteV1)
	routing.NewBlacklistsRouter(services.BlacklistService, baseRouteV1)

	return router
}
