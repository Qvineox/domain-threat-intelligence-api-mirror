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

	userGroupInsecure := userGroup.Group("")

	{
		userGroupInsecure.GET("/me", r.GetMe)
	}

	userGroup.Use(authMiddleware.RequireRole(2001))

	userWriteGroup := userGroup.Group("")
	userWriteGroup.Use(authMiddleware.RequireRole(2003))

	{
		userGroup.GET("/user/:user_id", r.GetUser)
		userGroup.GET("/users", r.GetUsers)

		userWriteGroup.PUT("/user", r.PutUser)
		userWriteGroup.PATCH("/user", r.PatchUser)
		userWriteGroup.DELETE("/user", r.DeleteUser)
	}

	{
		userGroup.GET("/permissions", r.GetPermissions)
		userGroup.GET("/permissions/presets", r.GetPermissionPresets)
	}

	{
		userGroup.POST("/password/reset", r.ResetPassword)
		userGroup.POST("/password/change", r.ChangePassword)
	}

	return &r
}

// PutUser accepts and creates user account
//
// @Summary            Create user account
// @Description        Accepts and creates user account
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/user [put]
// @ProduceAccessToken json
// @Param              user    body              userCreateParams true "user data"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *UsersRouter) PutUser(c *gin.Context) {
	var params userCreateParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	_, err = r.service.CreateUser(userEntities.PlatformUser{
		FullName: params.FullName,
		Login:    params.Login,
		Email:    params.Email,
		IsActive: params.IsActive,
	}, params.Password, params.PermissionIDs)

	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, 1)
}

type userCreateParams struct {
	Login         string   `json:"login" binding:"required"`
	FullName      string   `json:"fullName" binding:"required"`
	Email         string   `json:"email"`
	Password      string   `json:"password" binding:"required"`
	IsActive      bool     `json:"isActive"`
	PermissionIDs []uint64 `json:"permissionIDs" binding:"required"`
}

// PatchUser accepts and updates single user account
//
// @Summary            Update user account
// @Description        Accepts and updates single user account
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/user [patch]
// @ProduceAccessToken json
// @Param              user                 body          userUpdateParams true "user update"
// @Success            200                       {object} success.DatabaseResponse
// @Failure            404,401,400 {object} apiErrors.APIError
func (r *UsersRouter) PatchUser(c *gin.Context) {
	var params userUpdateParams

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
	}, params.PermissionIDs)

	if err != nil {
		if err.Error() == "user not found" {
			apiErrors.DatabaseEntityNotFound(c)
			return
		}

		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.PatchedResponse(c)
}

type userUpdateParams struct {
	ID            uint64   `json:"id" binding:"required"`
	Login         string   `json:"login" binding:"required"`
	FullName      string   `json:"fullName" binding:"required"`
	Email         string   `json:"email"`
	IsActive      bool     `json:"isActive"`
	PermissionIDs []uint64 `json:"permissionIDs" binding:"required"`
}

// DeleteUser accepts and deletes single user account
//
// @Summary            Delete user account
// @Description        Accepts and deletes single user account
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/user [delete]
// @ProduceAccessToken json
// @Param              id               body      byIDParams true "record ID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *UsersRouter) DeleteUser(c *gin.Context) {
	var params byIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteUser(params.ID)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// GetUsers returns all user accounts
//
// @Summary            Get all user accounts
// @Description        Returns all user accounts
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/users [get]
// @ProduceAccessToken json
// @Success            200              {object} []userEntities.PlatformUser
// @Failure            401,400 {object} apiErrors.APIError
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
// @Summary            Get single user account
// @Description        Returns single user account
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/user/{user_id} [get]
// @ProduceAccessToken json
// @Param              user_id path              int true "User ID"
// @Success            200              {object} userEntities.PlatformUser
// @Failure            401,400 {object} apiErrors.APIError
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
// @Summary            Get current session user
// @Description        Returns current session user in JWT token
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/me [get]
// @ProduceAccessToken json
// @Success            200              {object} userEntities.PlatformUser
// @Failure            401,400 {object} apiErrors.APIError
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

// GetPermissions returns all available permissions
//
// @Summary            Get all available permissions
// @Description        Returns all permissions
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/permissions [get]
// @ProduceAccessToken json
// @Success            200              {object} []userEntities.PlatformUserPermission
// @Failure            401,400 {object} apiErrors.APIError
func (r *UsersRouter) GetPermissions(c *gin.Context) {
	permissions, err := r.service.RetrievePermissions()
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// GetPermissionPresets returns all permission presets
//
// @Summary            Get all permission presets
// @Description        Returns all permission presets
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/permissions/presets [get]
// @ProduceAccessToken json
// @Success            200              {object} []userEntities.PlatformUserRolesPreset
// @Failure            401,400 {object} apiErrors.APIError
func (r *UsersRouter) GetPermissionPresets(c *gin.Context) {
	c.JSON(http.StatusOK, r.service.RetrievePermissionPresets())
}

// ResetPassword resets password for user
//
// @Summary            Reset password
// @Description        Resets password for user
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/password/reset [post]
// @ProduceAccessToken json
// @Param              id body byIDParams true "user to reset"
// @Success            200
// @Failure            404,401,400 {object} apiErrors.APIError
func (r *UsersRouter) ResetPassword(c *gin.Context) {
	var params byIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.ResetPassword(params.ID)
	if err != nil {
		if err.Error() == "user not found" {
			apiErrors.DatabaseEntityNotFound(c)
			return
		}

		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.Status(http.StatusOK)
}

// ChangePassword sets new password for user
//
// @Summary            Changes password for user
// @Description        Sets new password for user. Closes session
// @Tags               Users
// @Security           ApiKeyAuth
// @Router             /users/password/change [post]
// @ProduceAccessToken json
// @Param              id body changePasswordParams true "new password"
// @Success            200
// @Failure            404,401,400 {object} apiErrors.APIError
func (r *UsersRouter) ChangePassword(c *gin.Context) {
	var params changePasswordParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.ChangePassword(params.ID, params.OldPassword, params.NewPassword)
	if err != nil {
		if err.Error() == "user not found" {
			apiErrors.DatabaseEntityNotFound(c)
			return
		}

		if err.Error() == "password invalid" {
			apiErrors.ParamsErrorResponse(c, err)
			return
		}

		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.Status(http.StatusOK)
}

type changePasswordParams struct {
	ID          uint64 `json:"ID" binding:"required"`
	OldPassword string `json:"OldPassword" binding:"required"`
	NewPassword string `json:"NewPassword" binding:"required"`
}
