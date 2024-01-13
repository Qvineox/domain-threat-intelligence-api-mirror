package rest

import (
	"domain_threat_intelligence_api/api/rest/routing"
	"github.com/gin-gonic/gin"
)

// @title:       Domain Threat Intelligence API
// @version:     0.0.1
// @description: API provided by DTI project
// @contact.name Yaroslav Lysak
// @contact.url  https://t.me/Qvineox
// @host         localhost:7090
// @BasePath     /api/v1
func createRouter() *gin.Engine {
	router := gin.Default()

	baseRoute := router.Group("/api/v1")

	// maintenance API group
	routing.HandleMaintenanceGroup(baseRoute)

	return router
}
