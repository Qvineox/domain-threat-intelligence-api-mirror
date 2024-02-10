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

	{
		systemStateGroup.GET("/dynamic", router.GetDynamicConfig)
		systemStateGroup.POST("/dynamic/smtp", router.PostUpdateSMTPConfig)
		systemStateGroup.POST("/dynamic/naumen", router.PostUpdateNaumenConfig)
		systemStateGroup.POST("/dynamic/naumen/blacklists", router.PostUpdateNaumenBlacklistServiceConfig)
	}

	return &router
}

// GetDynamicConfig returns info about current dynamic application config
//
//	@Summary			View application dynamic config
//	@Description		Gets info about current dynamic application config
//	@Tags				Configuration
//	@Router				/system/dynamic [get]
//	@ProduceAccessToken	json
//	@Success			200
//	@Failure			400	{object}	apiErrors.APIError
//	@Failure			401	{object}	apiErrors.APIError
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
//	@Router				/system/dynamic/smtp [post]
//	@ProduceAccessToken	json
//	@Param				smtpConfig	body	smtpConfigUpdateParams	true	"dynamic SMTP configuration"
//	@Success			202
//	@Failure			400	{object}	error.APIError
func (r *SystemStateRouter) PostUpdateSMTPConfig(c *gin.Context) {
	params := smtpConfigUpdateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.UpdateSMTPConfig(params.Enabled, params.Host, params.User, params.Password, params.Sender, params.UseTLS)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	c.Status(http.StatusAccepted)
}

type smtpConfigUpdateParams struct {
	Enabled  bool   `json:"Enabled"`
	Host     string `json:"Host" binding:"required"`
	User     string `json:"User" binding:"required"`
	Password string `json:"Password" binding:"required"`
	Sender   string `json:"Sender" binding:"required"`
	UseTLS   bool   `json:"UseTLS"`
}

// PostUpdateNaumenConfig updates dynamic Naumen Service Desk configuration
//
//	@Summary			Update dynamic Naumen Service Desk configuration
//	@Description		Updates dynamic Naumen Service Desk configuration
//	@Tags				Configuration
//	@Router				/system/dynamic/naumen [post]
//	@ProduceAccessToken	json
//	@Param				naumenConfig	body	naumenConfigUpdateParams	true	"dynamic naumen configuration"
//	@Success			202
//	@Failure			400	{object}	error.APIError
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
//	@Router				/system/dynamic/naumen/blacklists [post]
//	@ProduceAccessToken	json
//	@Param				naumenConfig	body	naumenBlacklistServiceConfigUpdateParams	true	"dynamic naumen service configuration"
//	@Success			202
//	@Failure			400	{object}	error.APIError
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
	AgreementID uint64   `json:"agreementID" binding:"required"`
	SLM         uint64   `json:"SLM" binding:"required"`
	CallType    string   `json:"CallType" binding:"required"`
	HostTypes   []string `json:"HostTypes" binding:"required"`
}
