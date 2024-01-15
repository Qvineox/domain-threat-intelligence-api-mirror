package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
)

type BlacklistedIP struct {
	IPAddress pgtype.Inet `json:"IPAddress" gorm:"column:ip_address;type:inet;not_null;uniqueIndex:idx_ip"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"SourceID" gorm:"uniqueIndex:idx_ip"`

	gorm.Model
}
