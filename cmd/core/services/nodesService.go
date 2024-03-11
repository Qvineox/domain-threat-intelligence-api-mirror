package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"github.com/jackc/pgtype"
)

type NodesServiceImpl struct {
	repo core.INetworkNodesRepo
}

func NewNodesServiceImpl(repo core.INetworkNodesRepo) *NodesServiceImpl {
	return &NodesServiceImpl{repo: repo}
}

func (n NodesServiceImpl) RetrieveNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error) {
	return n.repo.SelectNetworkNodeByUUID(uuid)
}

func (n NodesServiceImpl) RetrieveNetworkNodesByFilter() ([]networkEntities.NetworkNode, error) {
	//TODO implement me
	panic("implement me")
}

func (n NodesServiceImpl) SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error) {
	//TODO implement me
	panic("implement me")
}

func (n NodesServiceImpl) DeleteNetworkNode(uuid pgtype.UUID) error {
	//TODO implement me
	panic("implement me")
}
