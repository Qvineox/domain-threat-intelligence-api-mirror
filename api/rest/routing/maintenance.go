package routing

import (
	"domain_threat_intelligence_api/cmd/core/entities"
	"github.com/gin-gonic/gin"
	"net/http"
)

func HandleMaintenanceGroup(path *gin.RouterGroup) {
	maintenanceGroup := path.Group("/maintenance")

	{
		maintenanceGroup.GET("/ping", Ping)
	}
}

// Ping returns info about application availability and status
//
//	@Summary		application availability and status
//	@Description	Gets info about application availability and status
//	@Tags			Maintenance
//	@Router			/maintenance/ping [get]
//	@Success		200	{object}	entities.AppStatus
func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, entities.AppStatus{Status: "all good!"})
}
