package entities

import "gorm.io/gorm"

type BlacklistedDomain struct {
	URN string `json:"URN" gorm:"column:URN;not_null;size:256"`

	// Defines source from where blacklisted host was added
	Source   BlacklistSource `json:"source" gorm:"foreignKey:SourceID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	SourceID uint64          `json:"source_id"`

	gorm.Model
}
