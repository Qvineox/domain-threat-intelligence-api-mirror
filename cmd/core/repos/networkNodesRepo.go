package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"gorm.io/gorm"
)

type NetworkNodesRepoImpl struct {
	*gorm.DB
}

func NewNetworkNodesRepoImpl(DB *gorm.DB) *NetworkNodesRepoImpl {
	return &NetworkNodesRepoImpl{DB: DB}
}

func (n NetworkNodesRepoImpl) SelectOrCreateByTarget(target jobEntities.Target) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{
		Identity: target.Host,
		TypeID:   uint64(target.Type) + 1, // cant be changed (in proto file must start with 0)
	}

	err := n.FirstOrCreate(&node).Error

	return node, err
}

func (n NetworkNodesRepoImpl) SaveNetworkNodeScan(scan networkEntities.NetworkNodeScan) error {
	return n.Save(&scan).Error
}

func (n NetworkNodesRepoImpl) CreateNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) error {
	node, err := n.SelectOrCreateByTarget(target)
	if err != nil {
		return err
	}

	scan.NodeUUID = node.UUID

	return n.SaveNetworkNodeScan(scan)
}
