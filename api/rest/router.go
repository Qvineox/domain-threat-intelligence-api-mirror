package rest

import (
	"domain_threat_intelligence_api/api/rest/auth"
	"domain_threat_intelligence_api/api/rest/routing"
	"github.com/gin-gonic/gin"
)

// ref: https://github.com/swaggo/gin-swagger/issues/90

// CreateRouter initializes application routing and all route groups
//
//	@title						Domain Threat Intelligence API
//	@version					0.0.3
//	@description				API provided by DTI project
//	@contact.name				Yaroslav Lysak
//	@contact.url				https://t.me/Qvineox
//	@Path						/api/v1
//	@securityDefinitions.apikey	ApiKeyAuth
//	@in							header
//	@name						x-api-Key
func CreateRouter(services Services, basePath string, authMiddleware *auth.MiddlewareService) *gin.Engine {
	router := gin.Default()

	router.MaxMultipartMemory = 16 << 25

	baseRouteV1 := router.Group(basePath)

	// API groups
	routing.NewBlacklistsRouter(services.BlacklistService, baseRouteV1, authMiddleware)
	routing.NewSystemStateRouter(services.SystemStateService, baseRouteV1, authMiddleware)
	routing.NewServiceDeskRouter(services.ServiceDeskService, baseRouteV1)
	routing.NewUsersRouter(services.UsersService, baseRouteV1, authMiddleware)

	routing.NewAuthRouter(services.AuthService, baseRouteV1)

	return router
}
