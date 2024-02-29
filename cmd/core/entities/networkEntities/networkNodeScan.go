package networkEntities

import (
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

// NetworkNodeScan represents unique scanning procedure on a single defined network node.
type NetworkNodeScan struct {
	ID uint64 `json:"UUID" gorm:"primaryKey"`

	IsComplete bool `json:"IsComplete" gorm:"default:false;not null"`

	// Defines parent node, scan object belongs to node object (many-to-one)
	Node     *NetworkNode `json:"Node,omitempty" gorm:"foreignKey:NodeUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	NodeUUID pgtype.UUID  `json:"NodeUUID;type:uuid"`

	ScanType   *NetworkNodeScanType `json:"Type,omitempty" gorm:"foreignKey:ScanTypeID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	ScanTypeID uint64               `json:"TypeID"`

	// Defines in which job scan result was created TODO
	// Job     *jobEntities.Job `json:"Job,omitempty" gorm:"foreignKey:JobUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	// JobUUID pgtype.UUID      `json:"JobUUID;type:uuid"`

	Data datatypes.JSON `json:"Data" gorm:"column:data"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

// NetworkNodeScanData represents contents of a NetworkNodeScan.
type NetworkNodeScanData struct {
}
