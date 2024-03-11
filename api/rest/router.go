package rest

import (
	"domain_threat_intelligence_api/api/rest/auth"
	"domain_threat_intelligence_api/api/rest/routing"
	"domain_threat_intelligence_api/api/socket"
	"domain_threat_intelligence_api/cmd/loggers"
	"domain_threat_intelligence_api/cmd/scheduler"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"time"
)

// ref: https://github.com/swaggo/gin-swagger/issues/90

// CreateRouter initializes application routing and all route groups
//
//	@title						Domain Threat Intelligence API
//	@version					0.0.4
//	@description				API provided by DTI project
//	@contact.name				Yaroslav Lysak
//	@contact.url				https://t.me/Qvineox
//	@Path						/api/v1
//	@securityDefinitions.apikey	ApiKeyAuth
//	@in							header
//	@name						x-api-Key
func CreateRouter(services Services, basePath string, allowedOrigins []string, authMiddleware *auth.MiddlewareService, sh *scheduler.Scheduler, pr time.Duration) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// logging
	router.Use(loggers.NewGINLogger().ProvideMiddleware(), gin.Recovery())

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
	routing.NewJobsRouter(services.JobsService, baseRouteV1, authMiddleware)
	routing.NewAuthRouter(services.AuthService, baseRouteV1, authMiddleware)
	routing.NewNodesRouter(services.NetworkNodesService, baseRouteV1, authMiddleware)

	scanningRoute := baseRouteV1.Group("/scanning")
	scanningRoute.Use(authMiddleware.RequireAuth())

	routing.NewQueueRouter(services.QueueService, scanningRoute, authMiddleware)
	routing.NewAgentsRouter(services.AgentsService, scanningRoute, authMiddleware)

	// web socket server configuration
	socket.NewWebSocketServer(baseRouteV1, sh, pr)

	return router
}
