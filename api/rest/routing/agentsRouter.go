package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"net"
	"net/http"
)

type AgentsRouter struct {
	service core.IAgentsService

	path           *gin.RouterGroup
	authMiddleware *auth.MiddlewareService
}

func NewAgentsRouter(service core.IAgentsService, path *gin.RouterGroup, authMiddleware *auth.MiddlewareService) *AgentsRouter {
	r := &AgentsRouter{service: service, path: path, authMiddleware: authMiddleware}

	agentsGroup := path.Group("/agents")

	agentsViewSecure := agentsGroup.Group("")
	agentsViewSecure.Use(authMiddleware.RequireRole(5201))

	{
		agentsViewSecure.GET("/agents", r.GetAllAgents)
		agentsViewSecure.GET("/agent/:agent_uuid", r.GetAgent)
	}

	agentsModifySecure := agentsGroup.Group("")
	agentsModifySecure.Use(authMiddleware.RequireRole(5202))

	{
		agentsModifySecure.PATCH("/agent", r.PatchAgent)
		agentsModifySecure.PUT("/agent", r.PutAgent)
		agentsModifySecure.DELETE("/agent", r.DeleteAgent)
	}

	return r
}

// GetAllAgents returns all registered agents
//
// @Summary            Get all scanning agent
// @Description        Returns all registered agents
// @Tags               Agents
// @Security           ApiKeyAuth
// @Router             /scanning/agents/agents [get]
// @ProduceAccessToken json
// @Success            200              {object} []agentEntities.ScanAgent
// @Failure            401,400 {object} apiErrors.APIError
func (r AgentsRouter) GetAllAgents(c *gin.Context) {
	agents, err := r.service.RetrieveAllAgents()
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, agents)
}

// GetAgent return registered agent by UUID
//
// @Summary            Get scanning agent by UUID
// @Description        Return registered agent by UUID
// @Tags               Agents
// @Security           ApiKeyAuth
// @Router             /scanning/agents/agent/{agent_uuid} [get]
// @ProduceAccessToken json
// @Param              agent_uuid path          string   true "Agent UUID"
// @Success            200                      {object} agentEntities.ScanAgent
// @Failure            401,400         {object} apiErrors.APIError
func (r AgentsRouter) GetAgent(c *gin.Context) {
	agentUUID := c.Param("agent_uuid")
	if agentUUID == "" {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	uuid := pgtype.UUID{}
	err := uuid.Set(agentUUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	agent, err := r.service.RetrieveAgentByUUID(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	} else if agent.UUID == nil {
		apiErrors.DatabaseEntityNotFound(c)
		return
	}

	c.JSON(http.StatusOK, agent)
}

// PutAgent accepts and creates scanning agent
//
// @Summary            Create scanning agent
// @Description        Accepts and creates scanning agent
// @Tags               Agents
// @Security           ApiKeyAuth
// @Router             /scanning/agents/agent [put]
// @ProduceAccessToken json
// @Param              user body scanAgentParams true "agent data"
// @Success            200
// @Failure            401,400 {object} apiErrors.APIError
func (r AgentsRouter) PutAgent(c *gin.Context) {
	var params scanAgentParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	var ownerID *uint64 = nil
	if params.OwnerID != nil {
		ownerID = params.OwnerID
	}

	host, _, err := net.SplitHostPort(params.Host)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	ipAddress := pgtype.Inet{}
	err = ipAddress.Set(host)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	_, err = r.service.CreateAgent(agentEntities.ScanAgent{
		Name:        params.Name,
		IPAddress:   ipAddress,
		Host:        params.Host,
		IsActive:    params.IsActive,
		IsHomeBound: params.IsHomeBound,
		Description: params.Description,
		MinPriority: uint64(params.MinPriority),
		OwnerID:     ownerID,
		IsPrivate:   params.IsPrivate,
	})

	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.Status(http.StatusOK)
}

// PatchAgent accepts and updates scanning agent
//
// @Summary            Update scanning agent
// @Description        Accepts and updates scanning agent
// @Tags               Agents
// @Security           ApiKeyAuth
// @Router             /scanning/agents/agent [patch]
// @ProduceAccessToken json
// @Param              user body scanAgentParams true "agent data"
// @Success            200
// @Failure            401,400 {object} apiErrors.APIError
func (r AgentsRouter) PatchAgent(c *gin.Context) {
	var params scanAgentParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if len(params.UUID) == 0 {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	var agentUUID = &pgtype.UUID{}
	err = agentUUID.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	var ownerID *uint64 = nil
	if params.OwnerID != nil {
		ownerID = params.OwnerID
	}

	host, _, err := net.SplitHostPort(params.Host)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	ipAddress := pgtype.Inet{}
	err = ipAddress.Set(host)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	_, err = r.service.UpdateAgent(agentEntities.ScanAgent{
		UUID:        agentUUID,
		Name:        params.Name,
		IPAddress:   ipAddress,
		Host:        params.Host,
		IsActive:    params.IsActive,
		IsHomeBound: params.IsHomeBound,
		Description: params.Description,
		MinPriority: uint64(params.MinPriority),
		OwnerID:     ownerID,
		IsPrivate:   params.IsPrivate,
	})

	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.Status(http.StatusOK)
}

// DeleteAgent accepts and deletes single scanning agent
//
// @Summary            Delete scanning agent
// @Description        Accepts and deletes single scanning agent
// @Tags               Agents
// @Security           ApiKeyAuth
// @Router             /scanning/agents/agent [delete]
// @ProduceAccessToken json
// @Param              id body byUUIDParams true "agent UUID to delete"
// @Success            200
// @Failure            401,400 {object} apiErrors.APIError
func (r AgentsRouter) DeleteAgent(c *gin.Context) {
	var params byUUIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	err = r.service.DeleteAgent(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.Status(http.StatusOK)
}

type scanAgentParams struct {
	UUID string `json:"UUID"`

	Name        string `json:"Name" binding:"required"`
	Host        string `json:"Host" binding:"required"`
	Description string `json:"Description"`

	IsActive    bool `json:"IsActive"`
	IsPrivate   bool `json:"IsPrivate"`
	IsHomeBound bool `json:"IsHomeBound"`

	MinPriority jobEntities.JobPriority `json:"MinPriority"`

	OwnerID *uint64 `json:"OwnerID"`
}
