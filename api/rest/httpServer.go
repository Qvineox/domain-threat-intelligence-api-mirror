package rest

import (
	"domain_threat_intelligence_api/api/rest/auth"
	"domain_threat_intelligence_api/cmd/core"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"log/slog"
	"net/http"
	"strings"
	"time"

	swaggerDocs "domain_threat_intelligence_api/docs/swagger" // needs to be imported to use Enabled docs
)

type HTTPServer struct {
	server *http.Server
	router *gin.Engine

	host string
	port uint64
}

func NewHTTPServer(host, path string, port uint64, services Services) (*HTTPServer, error) {
	s := &HTTPServer{}

	if len(host) == 0 {
		s.host = "0.0.0.0" // default address
	} else {
		s.host = host
	}

	if port == 0 {
		s.port = 80 // default port
	} else {
		s.port = port
	}

	// auth middleware construction
	authMiddleware := auth.NewMiddlewareService(services.AuthService)

	// gin router initialization
	s.router = CreateRouter(services, path, authMiddleware)

	// http server creation
	address := fmt.Sprintf("%s:%d", s.host, s.port)
	s.server = &http.Server{
		Addr:           address,
		Handler:        s.router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return s, nil
}

func (s *HTTPServer) EnableSwagger(host, version, path string) {
	swaggerDocs.SwaggerInfo.Host = host
	swaggerDocs.SwaggerInfo.Version = version
	swaggerDocs.SwaggerInfo.BasePath = path

	h := ginSwagger.WrapHandler(
		swaggerFiles.Handler,
		ginSwagger.PersistAuthorization(true),
		ginSwagger.DocExpansion("none"),
	)

	s.router.GET("/swagger/*any", h)
}

func (s *HTTPServer) ConfigureCORS(allowedOrigins []string) {
	slog.Info("cross-origin enabled for: " + strings.Join(allowedOrigins, ", "))

	s.router.Use(func(context *gin.Context) {
		slog.Info(context.GetHeader("origin"))
		slog.Info(context.GetHeader("referrer"))
	})

	s.router.Use(cors.New(cors.Config{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{"OPTIONS", "GET", "PUT", "PATCH", "DELETE", "POST"},
		AllowHeaders: []string{
			"Origin",
			"Host",
			"Access-Control-Allow-Origin",
			"Accept",
			"Cache-Control",
			"Content-Type",
			"Content-Length",
			"X-CSRF-Token",
			"Accept-Encoding",
			"Authorization",
			"X-Forwarded-*",
			"X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowWildcard:    true,
		MaxAge:           12 * time.Hour,
	}))
}

func (s *HTTPServer) Start() error {
	return s.server.ListenAndServe()
}

type Services struct {
	BlacklistService   core.IBlacklistsService
	SystemStateService core.ISystemStateService
	ServiceDeskService core.IServiceDeskService
	UsersService       core.IUsersService
	AuthService        core.IAuthService
}
