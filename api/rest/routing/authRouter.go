package routing

import (
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthRouter struct {
	service core.IAuthService
	path    *gin.RouterGroup

	domain string
}

func NewAuthRouter(service core.IAuthService, path *gin.RouterGroup, domain string) *AuthRouter {
	router := AuthRouter{service: service, path: path, domain: domain}

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

// Login accepts login and password, return pair of auth tokens
//
// @Summary            Authorizes user by login and password
// @Description        Accepts login and password, return pair of auth tokens
// @Tags               Auth
// @Router             /auth/login [post]
// @ProduceAccessToken json
// @Param              username body loginParams true "user credentials"
func (r *AuthRouter) Login(c *gin.Context) {
	var params loginParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	// TODO: session auth

	accessToken, refreshToken, err := r.service.Login(params.Username, params.Password)
	if err != nil {
		apiErrors.AuthErrorResponse(c, err)
		return
	}

	c.SetCookie("refresh_token", refreshToken, 60*60*48, "", r.domain, true, true)
	c.JSON(http.StatusAccepted, accessToken)
}

type loginParams struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (r *AuthRouter) Logout(c *gin.Context) {

}

func (r *AuthRouter) Refresh(c *gin.Context) {

}

func (r *AuthRouter) ConfirmEmail(c *gin.Context) {

}

func (r *AuthRouter) Register(c *gin.Context) {

}
