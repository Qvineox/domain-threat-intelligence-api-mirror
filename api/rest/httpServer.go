package rest

import (
	"domain_threat_intelligence_api/cmd/core"
	"fmt"
	"net/http"
	"time"

	swaggerDocs "domain_threat_intelligence_api/docs/swagger" // needs to be imported to use Swagger docs
)

type HTTPServer struct {
	server         *http.Server
	host           string
	port           uint64
	swaggerEnabled bool
}

func NewHTTPServer(host, swaggerHost, apiVersion, basePath, domain string, port uint64, swagger bool, services Services, allowedOrigins []string) (*HTTPServer, error) {
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

	// gin router initialization
	router := CreateRouter(services, basePath, domain, allowedOrigins)

	// swagger routing
	s.swaggerEnabled = swagger
	if s.swaggerEnabled {
		swaggerDocs.SwaggerInfo.Host = swaggerHost
		swaggerDocs.SwaggerInfo.Version = apiVersion
		swaggerDocs.SwaggerInfo.BasePath = basePath

		handleSwagger(router)
	}

	// http server creation
	address := fmt.Sprintf("%s:%d", s.host, s.port)
	s.server = &http.Server{
		Addr:           address,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return s, nil
}

func (s *HTTPServer) Start() error {
	return s.server.ListenAndServe()
}

type Services struct {
	BlacklistService   core.IBlacklistsService
	SystemStateService core.ISystemStateService
	ServiceDeskService core.IServiceDeskService
	AuthService        core.IAuthService
	UsersService       core.IUsersService
}
