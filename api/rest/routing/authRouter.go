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
}

func NewAuthRouter(service core.IAuthService, path *gin.RouterGroup) *AuthRouter {
	router := AuthRouter{service: service, path: path}

	authGroup := path.Group("/auth")

	{
		authGroup.POST("/login", router.Login)
		authGroup.POST("/logout", router.Logout)
		authGroup.POST("/refresh", router.Refresh)

		authGroup.POST("/confirmation/:uuid", router.ConfirmEmail)
		//authGroup.POST("/self-registration", router.Register) // self-registration ???

		authGroup.POST("/password-strength", router.GetPasswordStrength)
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
// @Success            202
// @Failure            401,400 {object} apiErrors.APIError
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

	c.SetCookie("refresh_token", refreshToken, 60*60*48, "", r.service.GetDomain(), true, true)
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

// Register accepts user account data and register new platform user
//
// @Summary            Creates new user with defined data
// @Description        Accepts user account data and register new platform user
// @Tags               Auth
// @Router             /auth/registration [post]
// @ProduceAccessToken json
// @Param              username body loginParams true "user credentials"
// @Success            202
// @Failure            401,400 {object} apiErrors.APIError
func (r *AuthRouter) Register(c *gin.Context) {
	var params registerParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	userID, err := r.service.Register(params.Login, params.Password, params.FullName, params.Email, params.RoleIDs)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusCreated, struct {
		CreatedUserID uint64 `json:"createdUserID"`
	}{
		CreatedUserID: userID,
	})
}

type registerParams struct {
	Login    string   `json:"login" binding:"required"`
	FullName string   `json:"fullName" binding:"required"`
	Email    string   `json:"email" binding:"required"`
	Password string   `json:"password" binding:"required"`
	RoleIDs  []uint64 `json:"roleIDs" binding:"required"`
}

// GetPasswordStrength returns password strength
//
// @Summary            Get strength of a password
// @Description        Returns password strength
// @Tags               Auth
// @Router             /auth/password-strength [post]
// @ProduceAccessToken json
// @Param              id  body     passwordStrengthParams true "password"
// @Success            200 {object} passwordStrengthResponse
// @Failure            400 {object} apiErrors.APIError
func (r *AuthRouter) GetPasswordStrength(c *gin.Context) {
	var params passwordStrengthParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	level, crackTime, entropy := r.service.GetPasswordStrength(params.Password)

	c.JSON(http.StatusOK, passwordStrengthResponse{
		Level:     level,
		Entropy:   entropy,
		CrackTime: crackTime,
	})
}

type passwordStrengthParams struct {
	Password string `json:"Password" binding:"required"`
}

type passwordStrengthResponse struct {
	Level     int     `json:"Level"`
	Entropy   float64 `json:"Entropy"`
	CrackTime float64 `json:"CrackTime"`
}
