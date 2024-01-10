package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// NetworkNodeScan represents unique scanning procedure on a single defined network node.
type NetworkNodeScan struct {
	gorm.Model

	IsComplete bool `json:"is_complete" gorm:"default:false;not null"`

	// Defines parent node, scan object belongs to node object (many-to-one)
	Node     NetworkNode `json:"node" gorm:"foreignKey:NodeUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	NodeUUID pgtype.UUID `json:"node_uuid"`

	Data datatypes.JSONType[NetworkNodeScanData] `json:"data" gorm:"column:data"`
}

// NetworkNodeScanData represents contents of a NetworkNodeScan.
type NetworkNodeScanData struct {
}
