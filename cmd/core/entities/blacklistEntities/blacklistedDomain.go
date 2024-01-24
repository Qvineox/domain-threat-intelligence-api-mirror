package blacklistEntities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type BlacklistedDomain struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	URN         string `json:"URN" gorm:"column:urn;not_null;uniqueIndex:idx_domain"`
	Description string `json:"Description" gorm:"column:description"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"SourceID" gorm:"uniqueIndex:idx_domain"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
