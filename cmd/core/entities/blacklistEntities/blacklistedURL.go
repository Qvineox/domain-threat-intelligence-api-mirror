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

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
