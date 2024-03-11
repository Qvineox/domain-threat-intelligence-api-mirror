package networkEntities

import (
	"bytes"
	"encoding/json"
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

// NetworkNodeScan represents unique scanning procedure on a single defined network node.
type NetworkNodeScan struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	IsComplete bool `json:"IsComplete" gorm:"default:false;not null"`

	// Defines parent node, scan object belongs to node object (many-to-one)
	Node     *NetworkNode `json:"Node,omitempty" gorm:"foreignKey:NodeUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	NodeUUID pgtype.UUID  `json:"NodeUUID"`

	ScanType   *NetworkNodeScanType `json:"Type,omitempty" gorm:"foreignKey:ScanTypeID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	ScanTypeID uint64               `json:"TypeID"`

	// Defines in which job scan result was created
	JobUUID *pgtype.UUID `json:"JobUUID"`

	Data datatypes.JSON `json:"Data" gorm:"column:data"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

// NetworkNodeScanData represents contents of a NetworkNodeScan.
type NetworkNodeScanData struct {
}

func (scan *NetworkNodeScan) Compact() error {
	var err error
	var compacted bytes.Buffer

	//switch ScanType(scan.ScanTypeID) {
	//case SCAN_TYPE_OSS_VT:
	//	c := ossEntities.VTIPScanBody{}
	//	err = scan.Data.Scan(&c)
	//	if err != nil {
	//		return err
	//	}
	//
	//	// TODO: add compacting, remove redundant or null (N/A, or other) fields
	//default:
	//	slog.Warn("unsupported compact type")
	//	return nil
	//}

	err = json.Compact(&compacted, scan.Data)
	if err != nil {
		return err
	}

	scan.Data = compacted.Bytes()
	return nil
}
