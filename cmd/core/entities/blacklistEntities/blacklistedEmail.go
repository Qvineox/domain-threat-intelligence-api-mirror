package blacklistEntities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type BlacklistedEmail struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	Email       string `json:"Email" gorm:"column:email;not_null"`
	Description string `json:"Description" gorm:"column:description"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"SourceID" gorm:"uniqueIndex:idx_url"`

	// ImportEvent describes import session from where blacklisted host was added
	ImportEvent   *BlacklistImportEvent `json:"ImportEvent,omitempty"`
	ImportEventID *uint64               `json:"ImportEventID" gorm:"column:import_event_id"`

	// DiscoveredAt sets date of discovery, provided by source or inserted automatically on create
	DiscoveredAt time.Time `json:"DiscoveredAt" gorm:"autoCreateTime"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
