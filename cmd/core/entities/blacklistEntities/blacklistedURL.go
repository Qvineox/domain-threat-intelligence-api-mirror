package blacklistEntities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type BlacklistedURL struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	URL         string `json:"URL" gorm:"column:url;not_null"`
	MD5         string `json:"MD5" gorm:"column:md5;not_null;uniqueIndex:idx_url"`
	Description string `json:"Description" gorm:"column:description"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"SourceID" gorm:"uniqueIndex:idx_url"`

	// ImportEvent describes import session from where blacklisted host was added
	ImportEvent   *BlacklistImportEvent `json:"ImportEvent,omitempty" gorm:"foreignKey:ImportEventID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	ImportEventID *uint64               `json:"ImportEventID" gorm:"column:import_event_id"`

	// DiscoveredAt sets date of discovery, provided by source or inserted automatically on create
	DiscoveredAt time.Time `json:"DiscoveredAt" gorm:"autoCreateTime"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
