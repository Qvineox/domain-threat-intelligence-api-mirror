package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
)

type AgentsRepoImpl struct {
	*gorm.DB
}

func NewAgentsRepoImpl(DB *gorm.DB) *AgentsRepoImpl {
	return &AgentsRepoImpl{DB: DB}
}

func (r AgentsRepoImpl) SelectAllAgents() ([]agentEntities.ScanAgent, error) {
	var agents = make([]agentEntities.ScanAgent, 0)

	err := r.Find(&agents).Error
	if err != nil {
		return nil, err
	}

	return agents, nil
}

func (r AgentsRepoImpl) SelectAgentByUUID(uuid pgtype.UUID) (agentEntities.ScanAgent, error) {
	var agent agentEntities.ScanAgent

	err := r.Find(&agent, uuid).Error
	if err != nil {
		return agentEntities.ScanAgent{}, err
	}

	return agent, nil
}

func (r AgentsRepoImpl) SaveAgent(agent agentEntities.ScanAgent) (agentEntities.ScanAgent, error) {
	err := r.Save(&agent).Error

	if err != nil {
		return agentEntities.ScanAgent{}, err
	}

	return agent, nil
}

func (r AgentsRepoImpl) DeleteAgent(uuid pgtype.UUID) error {
	err := r.Where("uuid = ?", uuid).Delete(&agentEntities.ScanAgent{}).Error
	if err != nil {
		return err
	}

	return nil
}
