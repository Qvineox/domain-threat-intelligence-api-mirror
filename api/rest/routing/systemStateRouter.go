package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"github.com/gin-gonic/gin"
	"net/http"
)

type SystemStateRouter struct {
	service core.ISystemStateService
	path    *gin.RouterGroup
	auth    *auth.MiddlewareService
}

func NewSystemStateRouter(service core.ISystemStateService, path *gin.RouterGroup, auth *auth.MiddlewareService) *SystemStateRouter {
	router := SystemStateRouter{service: service, path: path}

	systemStateGroup := path.Group("/system")
	systemStateGroup.Use(auth.RequireAuth())
	systemStateGroup.Use(auth.RequireRole(6001))

	systemWriteStateGroup := systemStateGroup.Group("")
	systemWriteStateGroup.Use(auth.RequireRole(6002))

	{
		systemStateGroup.GET("/dynamic", router.GetDynamicConfig)

		systemWriteStateGroup.POST("/dynamic/smtp", router.PostUpdateSMTPConfig)
		systemWriteStateGroup.POST("/dynamic/naumen", router.PostUpdateNaumenConfig)
		systemWriteStateGroup.POST("/dynamic/naumen/blacklists", router.PostUpdateNaumenBlacklistServiceConfig)
	}

	systemResetStateGroup := systemStateGroup.Group("")
	systemResetStateGroup.Use(auth.RequireRole(6003))

	{
		systemResetStateGroup.POST("/dynamic/reset", router.PostResetConfig)
	}

	return &router
}

// GetDynamicConfig returns info about current dynamic application config
//
//	@Summary			View application dynamic config
//	@Description		Gets info about current dynamic application config
//	@Tags				Configuration
//	@Security			ApiKeyAuth
//	@Router				/system/dynamic [get]
//	@ProduceAccessToken	json
//	@Success			200
//	@Failure			401,400	{object}	apiErrors.APIError
//	@Security			ApiKeyAuth
func (r *SystemStateRouter) GetDynamicConfig(c *gin.Context) {
	config, err := r.service.RetrieveDynamicConfig()
	if err != nil {
		apiErrors.InternalErrorResponse(c, err)
		return
	}

	c.Data(http.StatusOK, "application/json", config)
}

// PostUpdateSMTPConfig updates dynamic SMTP configuration
//
//	@Summary			Update dynamic SMTP configuration
//	@Description		Updates dynamic SMTP configuration
//	@Tags				Configuration
//	@Security			ApiKeyAuth
//	@Router				/system/dynamic/smtp [post]
//	@ProduceAccessToken	json
//	@Param				smtpConfig	body	smtpConfigUpdateParams	true	"dynamic SMTP configuration"
//	@Success			202
//	@Failure			401,400	{object}	error.APIError
func (r *SystemStateRouter) PostUpdateSMTPConfig(c *gin.Context) {
	params := smtpConfigUpdateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.UpdateSMTPConfig(params.Enabled, params.SSL, params.UseAuth, params.Host, params.User, params.From, params.Password, params.Port)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	c.Status(http.StatusAccepted)
}

type smtpConfigUpdateParams struct {
	Enabled  bool   `json:"Enabled"`
	Host     string `json:"Host" binding:"required"`
	Port     int    `json:"Port" binding:"required"`
	UseAuth  bool   `json:"UseAuth"`
	User     string `json:"User"`
	From     string `json:"From" binding:"required"`
	Password string `json:"Password"`
	SSL      bool   `json:"SSL"`
}

// PostUpdateNaumenConfig updates dynamic Naumen Service Desk configuration
//
//	@Summary			Update dynamic Naumen Service Desk configuration
//	@Description		Updates dynamic Naumen Service Desk configuration
//	@Tags				Configuration
//	@Security			ApiKeyAuth
//	@Router				/system/dynamic/naumen [post]
//	@ProduceAccessToken	json
//	@Param				naumenConfig	body	naumenConfigUpdateParams	true	"dynamic naumen configuration"
//	@Success			202
//	@Failure			401,400	{object}	error.APIError
func (r *SystemStateRouter) PostUpdateNaumenConfig(c *gin.Context) {
	params := naumenConfigUpdateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.UpdateNSDCredentials(params.Enabled, params.URL, params.ClientKey, params.ClientID, params.ClientGroupID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	c.Status(http.StatusAccepted)
}

type naumenConfigUpdateParams struct {
	Enabled       bool   `json:"Enabled"`
	URL           string `json:"URL" binding:"required"`
	ClientID      uint64 `json:"ClientID" binding:"required"`
	ClientGroupID uint64 `json:"ClientGroupID" binding:"required"`
	ClientKey     string `json:"ClientKey" binding:"required"`
}

// PostUpdateNaumenBlacklistServiceConfig updates dynamic Naumen Service Desk service configuration
//
//	@Summary			Update dynamic Naumen Service Desk service configuration
//	@Description		Updates dynamic Naumen Service Desk service configuration
//	@Tags				Configuration
//	@Security			ApiKeyAuth
//	@Router				/system/dynamic/naumen/blacklists [post]
//	@ProduceAccessToken	json
//	@Param				naumenConfig	body	naumenBlacklistServiceConfigUpdateParams	true	"dynamic naumen service configuration"
//	@Success			202
//	@Failure			401,400	{object}	error.APIError
func (r *SystemStateRouter) PostUpdateNaumenBlacklistServiceConfig(c *gin.Context) {
	params := naumenBlacklistServiceConfigUpdateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.UpdateNSDBlacklistServiceConfig(params.AgreementID, params.SLM, params.CallType, params.HostTypes)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	c.Status(http.StatusAccepted)
}

type naumenBlacklistServiceConfigUpdateParams struct {
	AgreementID uint64   `json:"AgreementID" binding:"required"`
	SLM         uint64   `json:"SLM" binding:"required"`
	CallType    string   `json:"CallType" binding:"required"`
	HostTypes   []string `json:"HostTypes" binding:"required"`
}

// PostResetConfig resets all dynamic configuration variables
//
//	@Summary			Return all dynamic configuration variables to default
//	@Description		Resets all dynamic configuration variables
//	@Tags				Configuration
//	@Security			ApiKeyAuth
//	@Router				/system/dynamic/reset [post]
//	@ProduceAccessToken	json
//	@Success			202
//	@Failure			401,400	{object}	error.APIError
func (r *SystemStateRouter) PostResetConfig(c *gin.Context) {
	err := r.service.ReturnToDefault()
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	c.Status(http.StatusAccepted)
}
