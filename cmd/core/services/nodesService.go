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

func (n NodesServiceImpl) RetrieveNetworkNodesByFilter(filter networkEntities.NetworkNodeSearchFilter) ([]networkEntities.NetworkNode, error) {
	return n.repo.SelectNetworkNodesByFilter(filter)
}

func (n NodesServiceImpl) SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error) {
	return n.repo.SaveNetworkNode(node)
}

func (n NodesServiceImpl) DeleteNetworkNode(uuid pgtype.UUID) (int64, error) {
	return n.repo.DeleteNetworkNode(uuid)
}
