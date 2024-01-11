package entities

import (
	"database/sql"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type NetworkNode struct {
	UUID pgtype.UUID `json:"uuid" gorm:"primaryKey"`

	// Network node unique identity, can be any address or URI. Must be unique.
	Identity string `json:"identity" gorm:"column:identity;size:128;not null;unique"`

	// Network node discovery timestamp, when was this node first found
	DiscoveredAt sql.NullTime `json:"discovered_at" gorm:"column:identity"`

	Type   NetworkNodeType `json:"node_type" gorm:"foreignKey:NodeUUID;constraint:OnUpdate:CASCADE;"`
	TypeID uint64          `json:"node_type_id"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
