package routing

import (
	"domain_threat_intelligence_api/cmd/core"
	"github.com/gin-gonic/gin"
)

type ServiceDeskRouter struct {
	service core.IServiceDeskService
	path    *gin.RouterGroup
}

func NewServiceDeskRouter(service core.IServiceDeskService, path *gin.RouterGroup) *ServiceDeskRouter {
	router := ServiceDeskRouter{service: service, path: path}

	serviceDeskGroup := path.Group("/service_desk")

	{
		serviceDeskGroup.GET("/availability", router.GetAvailability)
		serviceDeskGroup.GET("/ticket", router.GetTicketsByFilter)
		serviceDeskGroup.DELETE("/ticket/:id", router.DeleteTicket)
	}

	return &router
}

func (r *ServiceDeskRouter) GetAvailability(c *gin.Context) {

}

func (r *ServiceDeskRouter) GetTicketsByFilter(c *gin.Context) {

}

func (r *ServiceDeskRouter) DeleteTicket(c *gin.Context) {

}
