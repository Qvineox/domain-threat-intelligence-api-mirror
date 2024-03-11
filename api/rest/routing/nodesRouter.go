package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"net/http"
	"time"
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
	// nodesViewSecure.Use(authMiddleware.RequireRole(5201))

	{
		nodesViewSecure.GET("/nodes", r.GetNodesByFilter)
		nodesViewSecure.GET("/node/:node_uuid", r.GetNodeByUUID)
	}

	nodesModifySecure := nodesGroup.Group("")
	// nodesModifySecure.Use(authMiddleware.RequireRole(5202))

	{
		nodesModifySecure.PATCH("/node", r.PatchNode)
		nodesModifySecure.PUT("/node", r.PutNode)
		nodesModifySecure.DELETE("/node", r.DeleteNode)
	}

	return r
}

// GetNodesByFilter accepts filters and returns network nodes
//
// @Summary            Returns network nodes by filter
// @Description        Accepts filters and returns network nodes
// @Tags               Nodes
// @Security           ApiKeyAuth
// @Router             /nodes/nodes [get]
// @ProduceAccessToken json
// @Param              type_id[]                      query  []uint64 false "Node type IDs" collectionFormat(multi)
// @Param              discovered_after  query string        false    "Discovery timestamp is after"
// @Param              discovered_before query string        false    "Discovery timestamp is before"
// @Param              created_after     query        string          false "Created timestamp is after"
// @Param              created_before    query        string          false "Created timestamp is before"
// @Param              search_string     query        string          false "Substring to search"
// @Param              limit                          query           int     true  "Query limit"
// @Param              offset                         query           int     false "Query offset"
// @ProduceAccessToken application/csv
// @Success            200              {file}  file
// @Failure            401,400 {object} apiErrors.APIError
func (r *NodesRouter) GetNodesByFilter(c *gin.Context) {
	params := networkEntities.NetworkNodeSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	nodes, err := r.service.RetrieveNetworkNodesByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, nodes)
}

// GetNodeByUUID accepts UUID and returns saved NetworkNode
//
// @Summary            Get single node by UUID
// @Description        Returns single node
// @Tags               Nodes
// @Security           ApiKeyAuth
// @Router             /nodes/node/{node_uuid} [get]
// @ProduceAccessToken json
// @Param              node_uuid   path      string   true "Node UUID"
// @Success            200                   {object} networkEntities.NetworkNode
// @Failure            404,401,400 {object} apiErrors.APIError
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
