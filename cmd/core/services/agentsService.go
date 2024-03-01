package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"github.com/jackc/pgtype"
)

type AgentsServiceImpl struct {
	repo core.IAgentsRepo
}

func NewAgentsServiceImpl(repo core.IAgentsRepo) *AgentsServiceImpl {
	return &AgentsServiceImpl{repo: repo}
}

func (s AgentsServiceImpl) RetrieveAllAgents() ([]agentEntities.ScanAgent, error) {
	return s.repo.SelectAllAgents()
}

func (s AgentsServiceImpl) RetrieveAgentByUUID(uuid pgtype.UUID) (agentEntities.ScanAgent, error) {
	return s.repo.SelectAgentByUUID(uuid)
}

func (s AgentsServiceImpl) SaveAgent(agent agentEntities.ScanAgent) (agentEntities.ScanAgent, error) {
	return s.repo.SaveAgent(agent)
}

func (s AgentsServiceImpl) DeleteAgent(uuid pgtype.UUID) error {
	return s.repo.DeleteAgent(uuid)
}
