package rest

import (
	"fmt"
	"net/http"
	"time"

	_ "domain_threat_intelligence_api/docs/swagger" // needs to be imported to use Swagger docs
)

type HTTPServer struct {
	server         *http.Server
	host           string
	port           uint64
	swaggerEnabled bool
}

func NewHTTPServer(host string, port uint64, swagger bool) (*HTTPServer, error) {
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
	router := CreateRouter()

	// swagger routing
	s.swaggerEnabled = swagger
	if s.swaggerEnabled {
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

	// cors configuration // TODO

	return s, nil
}

func (s *HTTPServer) Start() error {
	return s.server.ListenAndServe()
}
