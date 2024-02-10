package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/api/rest/success"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

type UsersRouter struct {
	service        core.IUsersService
	path           *gin.RouterGroup
	authMiddleware *auth.MiddlewareService
}

func NewUsersRouter(service core.IUsersService, path *gin.RouterGroup, authMiddleware *auth.MiddlewareService) *UsersRouter {
	r := UsersRouter{service: service, path: path, authMiddleware: authMiddleware}

	userGroup := path.Group("/users")
	userGroup.Use(authMiddleware.RequireAuth())

	{
		userGroup.GET("/user/:user_id", r.GetUser)
		userGroup.GET("/users", r.GetUsers)
		userGroup.GET("/me", r.GetMe)

		userGroup.PATCH("/user", r.PatchUser)
		userGroup.DELETE("/user", r.DeleteUser)
	}

	{
		userGroup.GET("/roles", r.GetRoles)
	}

	{
		userGroup.POST("/password/reset", r.ResetPassword)
		userGroup.POST("/password/change", r.ChangePassword)
	}

	return &r
}

// PatchUser accepts and updates single user account
//
//	@Summary			Update user account
//	@Description		Accepts and updates single user account
//	@Tags				Users
//	@Security			ApiKeyAuth
//	@Router				/users/user [patch]
//	@ProduceAccessToken	json
//	@Param				user	body		userInsertParams	true	"user update"
//	@Success			200		{object}	success.DatabaseResponse
//	@Failure			400		{object}	apiErrors.APIError
func (r *UsersRouter) PatchUser(c *gin.Context) {
	var params userInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.SaveUser(userEntities.PlatformUser{
		ID:       params.ID,
		FullName: params.FullName,
		Login:    params.Login,
		Email:    params.Email,
		IsActive: params.IsActive,
	}, params.RoleIDs)

	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.PatchedResponse(c)
}

type userInsertParams struct {
	ID       uint64   `json:"id" binding:"required"`
	Login    string   `json:"login" binding:"required"`
	FullName string   `json:"fullName" binding:"required"`
	Email    string   `json:"email" binding:"required"`
	IsActive bool     `json:"isActive" binding:"required"`
	RoleIDs  []uint64 `json:"roleIDs" binding:"required"`
}

// DeleteUser accepts and deletes single user account
//
//	@Summary			Delete user account
//	@Description		Accepts and deletes single user account
//	@Tags				Users
//	@Security			ApiKeyAuth
//	@Router				/users/user [delete]
//	@ProduceAccessToken	json
//	@Param				id	body		deleteByIDParams	true	"record ID to delete"
//	@Success			200	{object}	success.DatabaseResponse
//	@Failure			400	{object}	apiErrors.APIError
//	@Failure			401	{object}	apiErrors.APIError
func (r *UsersRouter) DeleteUser(c *gin.Context) {
	var params deleteByIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteUser(params.ID)
	if err != nil {
		return
	}

	success.DeletedResponse(c, rows)
}

// GetUsers returns all user accounts
//
//	@Summary			Get all user accounts
//	@Description		Returns all user accounts
//	@Tags				Users
//	@Security			ApiKeyAuth
//	@Router				/users/users [get]
//	@ProduceAccessToken	json
//	@Success			200	{object}	[]userEntities.PlatformUser
//	@Failure			400	{object}	apiErrors.APIError
//	@Failure			401	{object}	apiErrors.APIError
func (r *UsersRouter) GetUsers(c *gin.Context) {
	users, err := r.service.RetrieveUsers()
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, users)
}

// GetUser returns single user account
//
//	@Summary			Get single user account
//	@Description		Returns single user account
//	@Tags				Users
//	@Security			ApiKeyAuth
//	@Router				/users/user/{user_id} [get]
//	@ProduceAccessToken	json
//	@Param				user_id	path		int	true	"User ID"
//	@Success			200		{object}	userEntities.PlatformUser
//	@Failure			400		{object}	apiErrors.APIError
func (r *UsersRouter) GetUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("user_id"), 10, 64)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	user, err := r.service.RetrieveUser(id)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	} else if user.ID == 0 {
		apiErrors.DatabaseEntityNotFound(c)
		return
	}

	c.JSON(http.StatusOK, user)
}

// GetMe returns current session user in JWT token
//
//	@Summary			Get current session user
//	@Description		Returns current session user in JWT token
//	@Tags				Users
//	@Security			ApiKeyAuth
//	@Router				/users/me [get]
//	@ProduceAccessToken	json
//	@Success			200	{object}	userEntities.PlatformUser
//	@Failure			400	{object}	apiErrors.APIError
//	@Failure			401	{object}	apiErrors.APIError
func (r *UsersRouter) GetMe(c *gin.Context) {
	contextUserID, ok := c.Get("user_id")
	if !ok {
		apiErrors.ParamsErrorResponse(c, errors.New("missing user id"))
		return
	}

	id, ok := contextUserID.(uint64)
	if !ok {
		apiErrors.ParamsErrorResponse(c, errors.New("failed to obtain user id"))
		return
	}

	user, err := r.service.RetrieveUser(id)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	} else if user.ID == 0 {
		apiErrors.DatabaseEntityNotFound(c)
		return
	}

	c.JSON(http.StatusOK, user)
}

// GetRoles returns all roles
//
//	@Summary			Get all roles
//	@Description		Returns all roles
//	@Tags				Users
//	@Security			ApiKeyAuth
//	@Router				/users/roles [get]
//	@ProduceAccessToken	json
//	@Success			200	{object}	[]userEntities.PlatformUserRole
//	@Failure			400	{object}	apiErrors.APIError
//	@Failure			401	{object}	apiErrors.APIError
func (r *UsersRouter) GetRoles(c *gin.Context) {
	roles, err := r.service.RetrieveRoles()
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, roles)
}

func (r *UsersRouter) ResetPassword(c *gin.Context) {
	//TODO implement me
	panic("implement me")
}

func (r *UsersRouter) ChangePassword(c *gin.Context) {
	//TODO implement me
	panic("implement me")
}
