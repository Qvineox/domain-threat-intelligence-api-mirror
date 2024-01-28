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
		systemStateGroup.POST("/dynamic/variable", router.PostDynamicConfigValue)
	}

	return &router
}

// GetDynamicConfig returns info about current dynamic application config
//
// @Summary     view application dynamic config
// @Description Gets info about current dynamic application config
// @Tags        Configuration
// @Router      /system/dynamic [get]
// @Success     200
// @Failure     400 {object} error.APIError
func (r *SystemStateRouter) GetDynamicConfig(c *gin.Context) {
	config, err := r.service.RetrieveDynamicConfig()
	if err != nil {
		error.InternalErrorResponse(c, err)
		return
	}

	c.Data(http.StatusOK, "application/json", config)
}

// PostDynamicConfigValue updates dynamic config variable
//
// @Summary     update dynamic config variable
// @Description Updates dynamic application config variable
// @Tags        Configuration
// @Router      /system/dynamic/variable [post]
// @Param       variable body dynamicConfigUpdateParams true "variable to update"
// @Success     202
// @Failure     400 {object} error.APIError
func (r *SystemStateRouter) PostDynamicConfigValue(c *gin.Context) {
	params := dynamicConfigUpdateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.SaveDynamicConfigVariable(params.DynamicConfigVariable, params.DynamicConfigValue)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	c.Status(http.StatusAccepted)
}

type dynamicConfigUpdateParams struct {
	DynamicConfigVariable string `json:"DynamicConfigVariable" binding:"required"`
	DynamicConfigValue    string `json:"DynamicConfigValue"`
}
