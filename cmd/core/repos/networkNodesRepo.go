package repos

import (
	"database/sql"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"errors"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type NetworkNodesRepoImpl struct {
	*gorm.DB
}

func NewNetworkNodesRepoImpl(DB *gorm.DB) *NetworkNodesRepoImpl {
	return &NetworkNodesRepoImpl{DB: DB}
}

func (n NetworkNodesRepoImpl) SelectOrCreateByTarget(target jobEntities.Target) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{}

	err := n.
		Where("identity = ? AND type_id = ?", target.Host, target.Type+1).
		Attrs(networkEntities.NetworkNode{
			Identity:     target.Host,
			DiscoveredAt: sql.NullTime{Time: time.Now()},
			TypeID:       uint64(target.Type + 1),
		}).
		FirstOrCreate(&node).Error

	return node, err
}

func (n NetworkNodesRepoImpl) SaveNetworkNodeScan(scan networkEntities.NetworkNodeScan) error {
	return n.Save(&scan).Error
}

func (n NetworkNodesRepoImpl) CreateNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) error {
	err := scan.Compact()
	if err != nil {
		return errors.New("failed to compact json message: " + err.Error())
	}

	node, err := n.SelectOrCreateByTarget(target)
	if err != nil {
		return err
	}

	scan.NodeUUID = node.UUID

	return n.SaveNetworkNodeScan(scan)
}

func (n NetworkNodesRepoImpl) SelectNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{}

	err := n.Find(&node, uuid).Error
	if err != nil {
		return networkEntities.NetworkNode{}, err
	}

	return node, nil
}
