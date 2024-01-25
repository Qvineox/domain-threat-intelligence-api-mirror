package routing

import (
	error "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"github.com/gin-gonic/gin"
	"net/http"
)

type SystemStateRouter struct {
	service core.ISystemStateService
	path    *gin.RouterGroup
}

func NewSystemStateRouter(service core.ISystemStateService, path *gin.RouterGroup) *SystemStateRouter {
	router := SystemStateRouter{service: service, path: path}

	systemStateGroup := path.Group("/system")

	{
		systemStateGroup.GET("/dynamic", router.GetDynamicConfig)
	}

	return &router
}

// GetDynamicConfig returns info about current dynamic application config
//
//	@Summary		application dynamic config
//	@Description	Gets info about current dynamic application config
//	@Tags			Configuration
//	@Router			/system/dynamic [get]
//	@Success		200
func (r *SystemStateRouter) GetDynamicConfig(c *gin.Context) {
	config, err := r.service.RetrieveDynamicConfig()
	if err != nil {
		error.InternalErrorResponse(c, err)
		return
	}

	c.Data(http.StatusOK, "application/json", config)
}