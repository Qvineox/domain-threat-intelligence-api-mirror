package entities

import "gorm.io/gorm"

type BlacklistedDomain struct {
	URN string `json:"urn" gorm:"column:urn;not_null;size:256;uniqueIndex:idx_domain"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"source_id" gorm:"uniqueIndex:idx_domain"`

	gorm.Model
}
