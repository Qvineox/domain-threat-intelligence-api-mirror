package rest

import (
	"domain_threat_intelligence_api/api/rest/auth"
	"domain_threat_intelligence_api/api/rest/routing"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"time"
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
func CreateRouter(services Services, basePath string, allowedOrigins []string, authMiddleware *auth.MiddlewareService) *gin.Engine {
	router := gin.Default()

	// CORS configurations
	router.Use(cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{"OPTIONS", "GET", "PUT", "PATCH", "DELETE", "POST"},
		AllowHeaders: []string{
			"Accept",
			"Cache-Control",
			"Content-Type",
			"Content-Length",
			"X-CSRF-Token",
			"X-API-Key",
			"Accept-Encoding",
			"Accept-Language",
			"Authorization",
			"X-Forwarded-*",
			"X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowWildcard:    true,
		MaxAge:           12 * time.Hour,
	}))

	router.MaxMultipartMemory = 16 << 25

	baseRouteV1 := router.Group(basePath)

	// API groups
	routing.NewBlacklistsRouter(services.BlacklistService, baseRouteV1, authMiddleware)
	routing.NewSystemStateRouter(services.SystemStateService, baseRouteV1, authMiddleware)
	routing.NewServiceDeskRouter(services.ServiceDeskService, baseRouteV1)
	routing.NewUsersRouter(services.UsersService, baseRouteV1, authMiddleware)

	routing.NewAuthRouter(services.AuthService, baseRouteV1, authMiddleware)

	return router
}
