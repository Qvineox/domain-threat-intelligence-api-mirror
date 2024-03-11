package networkEntities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type NetworkNode struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	// Network node unique identity, can be any address or URI. Must be unique.
	Identity string `json:"Identity" gorm:"column:identity;size:128;not null;unique"`

	// Network node discovery timestamp, when was this node first found
	DiscoveredAt *time.Time `json:"DiscoveredAt" gorm:"column:discovered_at"`

	Type   *NetworkNodeType `json:"NodeType,omitempty" gorm:"foreignKey:TypeID;constraint:OnUpdate:CASCADE;OnDelete:SET NULL"`
	TypeID uint64           `json:"NodeTypeId"`

	Scans []NetworkNodeScan `json:"Scans" gorm:"foreignKey:NodeUUID"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
