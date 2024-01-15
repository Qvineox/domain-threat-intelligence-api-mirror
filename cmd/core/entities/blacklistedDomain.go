package entities

import "gorm.io/gorm"

type BlacklistedDomain struct {
	URN string `json:"URN" gorm:"column:urn;not_null;size:256;uniqueIndex:idx_domain"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64           `json:"SourceID" gorm:"uniqueIndex:idx_domain"`

	gorm.Model
}
