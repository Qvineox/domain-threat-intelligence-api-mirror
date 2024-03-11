package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"net/http"
)

type NodesRouter struct {
	service core.INetworkNodesService

	path           *gin.RouterGroup
	authMiddleware *auth.MiddlewareService
}

func NewNodesRouter(service core.INetworkNodesService, path *gin.RouterGroup, authMiddleware *auth.MiddlewareService) *NodesRouter {
	r := &NodesRouter{service: service, path: path, authMiddleware: authMiddleware}

	nodesGroup := path.Group("/nodes")

	nodesViewSecure := nodesGroup.Group("")
	//nodesViewSecure.Use(authMiddleware.RequireRole(5201))

	{
		nodesViewSecure.GET("/nodes", r.GetNodesByFilter)
		nodesViewSecure.GET("/nodes/:node_uuid", r.GetNodeByUUID)
	}

	nodesModifySecure := nodesGroup.Group("")
	//nodesModifySecure.Use(authMiddleware.RequireRole(5202))

	{
		nodesModifySecure.PATCH("/node", r.PatchNode)
		nodesModifySecure.PUT("/node", r.PutNode)
		nodesModifySecure.DELETE("/node", r.DeleteNode)
	}

	return r
}

func (r *NodesRouter) GetNodesByFilter(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

// GetNodeByUUID accepts UUID and returns saved NetworkNode
//
//	@Summary			Get single node by UUID
//	@Description		Returns single node
//	@Tags				Nodes
//	@Security			ApiKeyAuth
//	@Router				/nodes/node/{node_uuid} [get]
//	@ProduceAccessToken	json
//	@Param				node_uuid	path		string	true	"Node UUID"
//	@Success			200			{object}	networkEntities.NetworkNode
//	@Failure			404,401,400	{object}	apiErrors.APIError
func (r *NodesRouter) GetNodeByUUID(c *gin.Context) {
	uuidParam := c.Param("node_uuid")
	if len(uuidParam) == 0 {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	uuid := pgtype.UUID{}
	err := uuid.Set(uuidParam)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	node, err := r.service.RetrieveNetworkNodeByUUID(uuid)
	if err != nil {
		return
	} else if node.UUID.Status == pgtype.Undefined {
		apiErrors.DatabaseEntityNotFound(c)
		return
	}

	c.JSON(http.StatusOK, node)
}

func (r *NodesRouter) PatchNode(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func (r *NodesRouter) PutNode(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func (r *NodesRouter) DeleteNode(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}
