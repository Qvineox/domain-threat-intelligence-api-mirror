package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/scheduler"
	"github.com/jackc/pgtype"
)

type AgentsServiceImpl struct {
	repo         core.IAgentsRepo
	jobScheduler *scheduler.Scheduler
}

func NewAgentsServiceImpl(repo core.IAgentsRepo, sch *scheduler.Scheduler) *AgentsServiceImpl {
	return &AgentsServiceImpl{repo: repo, jobScheduler: sch}
}

func (s AgentsServiceImpl) RetrieveAllAgents() ([]agentEntities.ScanAgent, error) {
	agents, err := s.repo.SelectAllAgents()
	if err != nil {
		return nil, err
	}

	uuids := s.jobScheduler.GetAllConnectedDialersUUIDs()
	for i, a := range agents {
		for _, u := range uuids {
			if *a.UUID == u {
				agents[i].IsConnected = true
			}
		}
	}

	return agents, nil
}

func (s AgentsServiceImpl) RetrieveAgentByUUID(uuid pgtype.UUID) (agentEntities.ScanAgent, error) {
	return s.repo.SelectAgentByUUID(uuid)
}

func (s AgentsServiceImpl) SaveAgent(agent agentEntities.ScanAgent) (agentEntities.ScanAgent, error) {
	agent, err := s.repo.SaveAgent(agent)
	if err != nil {
		return agentEntities.ScanAgent{}, err
	}

	err = s.jobScheduler.AddOrUpdateDialer(&agent)
	if err != nil {
		return agentEntities.ScanAgent{}, err
	}

	return s.repo.SaveAgent(agent)
}

func (s AgentsServiceImpl) DeleteAgent(uuid pgtype.UUID) error {
	err := s.repo.DeleteAgent(uuid)
	if err != nil {
		return err
	}

	err = s.jobScheduler.RemoveDialerByUUID(uuid)
	if err != nil {
		return err
	}

	return nil
}
