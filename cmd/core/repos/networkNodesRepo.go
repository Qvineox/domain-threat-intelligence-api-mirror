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

func (r NetworkNodesRepoImpl) SelectOrCreateByTarget(target jobEntities.Target) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{}

	err := r.
		Where("identity = ? AND type_id = ?", target.Host, target.Type+1).
		Attrs(networkEntities.NetworkNode{
			Identity:     target.Host,
			DiscoveredAt: sql.NullTime{Time: time.Now()},
			TypeID:       uint64(target.Type + 1),
		}).
		FirstOrCreate(&node).Error

	return node, err
}

func (r NetworkNodesRepoImpl) SelectNetworkNodesByFilter(filter networkEntities.NetworkNodeSearchFilter) ([]networkEntities.NetworkNode, error) {
	nodes := make([]networkEntities.NetworkNode, 0)

	// TODO: use query filters

	return nodes, nil
}

func (r NetworkNodesRepoImpl) SaveNetworkNode(node networkEntities.NetworkNode) (networkEntities.NetworkNode, error) {
	err := r.Save(&node).Error

	return node, err
}

func (r NetworkNodesRepoImpl) DeleteNetworkNode(uuid pgtype.UUID) (int64, error) {
	query := r.Where("UUID = ?", uuid).Delete(&networkEntities.NetworkNode{})

	return query.RowsAffected, query.Error
}

func (r NetworkNodesRepoImpl) SaveNetworkNodeScan(scan networkEntities.NetworkNodeScan) (networkEntities.NetworkNodeScan, error) {
	err := r.Save(&scan).Error

	return scan, err
}

func (r NetworkNodesRepoImpl) CreateNetworkNodeWithIdentity(scan networkEntities.NetworkNodeScan, target jobEntities.Target) error {
	err := scan.Compact()
	if err != nil {
		return errors.New("failed to compact json message: " + err.Error())
	}

	node, err := r.SelectOrCreateByTarget(target)
	if err != nil {
		return err
	}

	scan.NodeUUID = node.UUID

	_, err = r.SaveNetworkNodeScan(scan)
	return err
}

func (r NetworkNodesRepoImpl) SelectNetworkNodeByUUID(uuid pgtype.UUID) (networkEntities.NetworkNode, error) {
	node := networkEntities.NetworkNode{}

	err := r.Preload("Type").Preload("Scans").Find(&node, uuid).Error
	if err != nil {
		return networkEntities.NetworkNode{}, err
	}

	return node, nil
}
