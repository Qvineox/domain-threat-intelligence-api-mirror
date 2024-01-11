package entities

import (
	"gorm.io/gorm"
)

type BlacklistedDomain struct {
	gorm.Model

	URN    string `json:"URN" gorm:"column:URN;not_null;size:256"`
	Source string `json:"source" gorm:"column:source;size:128;default:manual input"`
}
