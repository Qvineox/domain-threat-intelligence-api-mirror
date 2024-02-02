package routing

import (
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"github.com/gin-gonic/gin"
)

type AuthRouter struct {
	service core.IAuthService
	path    *gin.RouterGroup
}

func NewAuthRouter(service core.IAuthService, path *gin.RouterGroup) *AuthRouter {
	router := AuthRouter{service: service, path: path}

	authGroup := path.Group("/auth")

	{
		authGroup.POST("/login", router.Login)
		authGroup.POST("/logout", router.Logout)
		authGroup.POST("/refresh", router.Refresh)

		authGroup.POST("/confirmation/:uuid", router.ConfirmEmail)
		authGroup.POST("/registration", router.Register)
	}

	return &router
}

// https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-storage-on-client-side

func (r *AuthRouter) Login(c *gin.Context) {
	var params struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	// TODO: session auth

	_, _, err = r.service.Login(params.Username, params.Password)
	if err != nil {
		apiErrors.AuthErrorResponse(c, err)
		return
	}

	//c.SetCookie("refresh_token", refresh, 60*60*48, "", s.serverConfig.Domain, true, true)
	//c.JSON(http.StatusAccepted, tokens)

}

func (r *AuthRouter) Logout(c *gin.Context) {

}

func (r *AuthRouter) Refresh(c *gin.Context) {

}

func (r *AuthRouter) ConfirmEmail(c *gin.Context) {

}

func (r *AuthRouter) Register(c *gin.Context) {

}
